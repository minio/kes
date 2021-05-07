// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package metric

import (
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// New returns a new Metrics that gathers and exposes various
// metrics about the application.
func New() *Metrics {
	metrics := &Metrics{
		registry: prometheus.NewRegistry(),
		requestSucceeded: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "kes",
			Subsystem: "http",
			Name:      "request_success",
			Help:      "Number of requests that have been served successfully.",
		}),
		requestErrored: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "kes",
			Subsystem: "http",
			Name:      "request_error",
			Help:      "Number of request that failed due to some error. (HTTP 4xx status code)",
		}),
		requestFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "kes",
			Subsystem: "http",
			Name:      "request_failure",
			Help:      "Number of request that failed due to some internal failure. (HTTP 5xx status code)",
		}),
		requestActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "kes",
			Subsystem: "http",
			Name:      "request_active",
			Help:      "Number of active requests that are not finished, yet.",
		}),
		requestLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "kes",
			Subsystem: "http",
			Name:      "response_time",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 1.5, 3.0, 5.0, 10.0}, // from 10ms to 10s
			Help:      "Histogram of request response times spawning from 10ms to 10s.",
		}),

		errorLogEvents: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "kes",
			Subsystem: "log",
			Name:      "error_events",
			Help:      "Number of error log events written to the error log targets.",
		}),
		auditLogEvents: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "kes",
			Subsystem: "log",
			Name:      "audit_events",
			Help:      "Number of audit log events written to the audit log targets.",
		}),

		startTime: time.Now(),
		upTimeInSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "kes",
			Subsystem: "system",
			Name:      "up_time",
			Help:      "The time the server has been up and running in seconds.",
		}),
	}

	metrics.registry.MustRegister(metrics.requestSucceeded)
	metrics.registry.MustRegister(metrics.requestErrored)
	metrics.registry.MustRegister(metrics.requestFailed)
	metrics.registry.MustRegister(metrics.requestActive)
	metrics.registry.MustRegister(metrics.requestLatency)
	metrics.registry.MustRegister(metrics.errorLogEvents)
	metrics.registry.MustRegister(metrics.auditLogEvents)
	metrics.registry.MustRegister(metrics.upTimeInSeconds)
	return metrics
}

// Metrics is a type that gathers various metrics and information
// about an application.
type Metrics struct {
	registry *prometheus.Registry

	requestSucceeded prometheus.Counter
	requestFailed    prometheus.Counter
	requestErrored   prometheus.Counter
	requestActive    prometheus.Gauge
	requestLatency   prometheus.Histogram

	errorLogEvents prometheus.Counter
	auditLogEvents prometheus.Counter

	startTime       time.Time // Used to compute the up time as upTime = now - startTime
	upTimeInSeconds prometheus.Gauge
}

// EncodeTo collects all outstanding metrics information
// about the application and writes it to encoder.
func (m *Metrics) EncodeTo(encoder expfmt.Encoder) error {
	m.upTimeInSeconds.Set(time.Since(m.startTime).Truncate(10 * time.Millisecond).Seconds())

	metrics, err := m.registry.Gather()
	if err != nil {
		return err
	}
	for _, metric := range metrics {
		if err := encoder.Encode(metric); err != nil {
			return err
		}
	}
	return nil
}

// Count returns a HandlerFunc that wraps h and counts the
// how many requests succeeded (HTTP 200 OK) and how many
// failed.
//
// Count distingushes requests that fail with some sort of
// well-defined error (HTTP 4xx) and requests that fail due
// to some internal error (HTTP 5xx).
func (m *Metrics) Count(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.requestActive.Inc()
		defer m.requestActive.Dec()

		h(&countResponseWriter{
			ResponseWriter: w,
			flusher:        w.(http.Flusher),
			succeeded:      m.requestSucceeded,
			errored:        m.requestErrored,
			failed:         m.requestFailed,
		}, r)
	}
}

// Latency returns a HandlerFunc that wraps h and measures the
// internal request-response latency.
//
// The internal request-response latency is the time the
// application takes to generate and send a response after
// receiving a request. It basically shows how many request
// the application can handle.
func (m *Metrics) Latency(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h(&latencyResponseWriter{
			ResponseWriter: w,
			flusher:        w.(http.Flusher),
			start:          time.Now(),
			histogram:      m.requestLatency,
		}, r)
	}
}

// ErrorEventCounter returns an io.Writer that increments
// the error event log counter on each write call.
//
// The returned io.Writer never returns an error on writes.
func (m *Metrics) ErrorEventCounter() io.Writer {
	return eventCounter{metric: m.errorLogEvents}
}

// AuditEventCounter returns an io.Writer that increments
// the audit event log counter on each write call.
//
// The returned io.Writer never returns an error on writes.
func (m *Metrics) AuditEventCounter() io.Writer {
	return eventCounter{metric: m.auditLogEvents}
}

type eventCounter struct {
	metric prometheus.Counter
}

func (w eventCounter) Write(p []byte) (int, error) {
	w.metric.Inc()
	return len(p), nil
}

// latencyResponseWriter is an http.ResponseWriter that
// measures the internal request-response latency.
type latencyResponseWriter struct {
	http.ResponseWriter
	flusher http.Flusher

	start     time.Time            // The point in time when the request was received
	histogram prometheus.Histogram // The latency histogram
	written   bool                 // Inidicates whether the HTTP headers have been written
}

var (
	_ http.ResponseWriter = (*latencyResponseWriter)(nil)
	_ http.Flusher        = (*latencyResponseWriter)(nil)
)

func (w *latencyResponseWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	if !w.written {
		w.histogram.Observe(time.Since(w.start).Seconds())
		w.written = true
	}
}

func (w *latencyResponseWriter) Flush() {
	if w.flusher != nil {
		w.flusher.Flush()
	}
}

// countResponseWriter is an http.ResponseWriter that
// counts the number of requests partition by requests
// that:
//   • Succeeded (HTTP 200 OK)
//   • Errored   (HTTP 4xx)
//   • Failed    (HTTP 5xx)
type countResponseWriter struct {
	http.ResponseWriter
	flusher http.Flusher

	succeeded prometheus.Counter
	errored   prometheus.Counter
	failed    prometheus.Counter
	written   bool // Inidicates whether the HTTP headers have been written
}

var (
	_ http.ResponseWriter = (*countResponseWriter)(nil)
	_ http.Flusher        = (*countResponseWriter)(nil)
)

func (w *countResponseWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	if !w.written {
		switch {
		case status == http.StatusOK:
			w.succeeded.Inc()
		case status >= 400 && status < 500:
			w.errored.Inc()
		case status >= 500 && status < 600:
			w.failed.Inc()
		default:
			// We panic to signal that the server returned a status code
			// that is not tracked. If, in the future, the application
			// returns a new (kind of) status code it should be collected
			// as well.
			// Otherwise, we would silently ignore new status codes and the
			// metrics would be incomplete.
			panic("metrics: unexpected response status code " + strconv.Itoa(status))
		}
		w.written = true
	}
}

func (w *countResponseWriter) Flush() {
	if w.flusher != nil {
		w.flusher.Flush()
	}
}
