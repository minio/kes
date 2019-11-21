package xhttp

import (
	"io"
	"net/http"
)

type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

func (h HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		if err, ok := err.(interface{ Status() int }); ok {
			w.WriteHeader(err.Status())
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		io.WriteString(w, err.Error())
	}
}

type MultiHandler []HandlerFunc

func (handlers MultiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, handler := range handlers {
		if err := handler(w, r); err != nil {
			if err, ok := err.(interface{ Status() int }); ok {
				w.WriteHeader(err.Status())
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			io.WriteString(w, err.Error())
			break
		}
	}
}
