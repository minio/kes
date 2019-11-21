package xhttp

import "net/http"

const NotFound status = http.StatusNotFound

type status int

func (code status) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "", int(code))
}

func LimitRequestBody(n int64) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.ContentLength < 0 {
			return Error(http.StatusLengthRequired, "")
		}
		if r.ContentLength > n {
			return Error(http.StatusRequestEntityTooLarge, "")
		}
		r.Body = http.MaxBytesReader(w, r.Body, r.ContentLength)
		return nil
	}
}

func RequireMethod(method string) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != method {
			w.Header().Set("Accept", method)
			return Error(http.StatusMethodNotAllowed, "")
		}
		return nil
	}
}
