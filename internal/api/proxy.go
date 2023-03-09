// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"net/http"

	"github.com/minio/kes/internal/auth"
)

func proxy(proxy *auth.TLSProxy, f http.Handler) http.Handler {
	if proxy == nil {
		return f
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := proxy.Verify(r); err != nil {
			Fail(w, err)
			return
		}
		f.ServeHTTP(w, r)
	})
}
