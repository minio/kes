// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"net/http"

	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/log"
)

// TLSProxy returns a handler function that checks if the
// request has been forwarded by a TLS proxy and, if so,
// verifies and adjusts the request such that handlers
// further down the stack can treat it as sent by the
// actual client.
//
// Therefore, it replaces the proxy certificate in the
// TLS connection state with the client certificate
// forwarded by the proxy as part of the request headers.
func TLSProxy(proxy *auth.TLSProxy, f http.HandlerFunc) http.HandlerFunc {
	if proxy == nil {
		return f
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO(aead): At the moment updating the audit log
		// identity via this type check is kind of a hack.
		// However, there is no simple and clean solution
		// that does not require some extended changes.
		// (One option may be another http.HandlerFunc type)
		// For now, we can keep this until we've sattled
		// on a cleaner solution.

		aw, ok := w.(*log.AuditResponseWriter)
		if err := proxy.Verify(r); err != nil {
			Error(w, err)
			return
		}
		if ok && aw != nil {
			// Update the audit log identity such that
			// the audit log shows the actual client and
			// not the TLS proxy.
			aw.Identity = auth.Identify(r, proxy.Identify)
		}
		f(w, r)
	}
}
