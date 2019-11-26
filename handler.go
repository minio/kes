package key

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/secure-io/sio-go/sioutil"
)

func RequireMethod(method string, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if method != r.Method {
			w.Header().Set("Accept", method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f(w, r)
	}
}

func LimitRequestBody(n int64, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		f(w, r)
	}
}

func EnforcePolicies(roles *Roles, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := roles.enforce(r); err != nil {
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		f(w, r)
	}
}

func HandleCreateKey(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type request struct {
			Bytes []byte `json:"bytes"`
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}

		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		var secret Secret
		if len(req.Bytes) > 0 && len(req.Bytes) != len(secret) {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}

		if len(req.Bytes) != len(secret) {
			bytes, err := sioutil.Random(len(secret))
			if err != nil {
				http.Error(w, err.Error(), statusCode(err))
				return
			}
			copy(secret[:], bytes)
		} else {
			copy(secret[:], req.Bytes)
		}
		if err := store.Create(name, secret); err != nil {
			http.Error(w, err.Error(), statusCode(err))
		}
	}
}

func HandleDeleteKey(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}
		if err := store.Delete(name); err != nil {
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleGenerateKey(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			Context []byte `json:"context"`
		}
		type Response struct {
			Plaintext  []byte `json:"plaintext"`
			Ciphertext []byte `json:"ciphertext"`
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}
		secret, err := store.Get(name)
		if err != nil {
			err = asStatusError(err, ErrKeyNotFound.Error(), ErrKeyNotFound.Status())
			http.Error(w, err.Error(), statusCode(err))
			return
		}

		dataKey, err := sioutil.Random(32)
		if err != nil {
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		ciphertext, err := secret.Wrap(dataKey, req.Context)
		if err != nil {
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		json.NewEncoder(w).Encode(Response{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
		})
	}
}

func HandleDecryptKey(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			Ciphertext []byte `json:"ciphertext"`
			Context    []byte `json:"context"`
		}
		type Response struct {
			Plaintext []byte `json:"plaintext"`
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}
		secret, err := store.Get(name)
		if err != nil {
			err = asStatusError(err, ErrKeyNotFound.Error(), ErrKeyNotFound.Status())
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		plaintext, err := secret.Unwrap(req.Ciphertext, req.Context)
		if err != nil {
			err = asStatusError(err, "not authentic", http.StatusBadRequest)
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		json.NewEncoder(w).Encode(Response{
			Plaintext: plaintext,
		})
	}
}

func HandleWritePolicy(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid policy name", http.StatusBadRequest)
			return
		}

		var policy Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		roles.Set(name, &policy)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleReadPolicy(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid policy name", http.StatusBadRequest)
			return
		}

		policy, ok := roles.Get(name)
		if !ok {
			http.Error(w, "policy does not exists", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(policy)
	}
}

func HandleListPolicies(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(roles.Policies()) }
}

func HandleDeletePolicy(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid policy name", http.StatusBadRequest)
			return
		}
		roles.Delete(name)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleAssignIdentity(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			Policy string `json:"policy"`
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		identity := Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			http.Error(w, "invalid identity", http.StatusBadRequest)
			return
		}
		if identity == roles.Root {
			http.Error(w, "identity is root", http.StatusBadRequest)
			return
		}
		if err := roles.Assign(req.Policy, identity); err != nil {
			http.Error(w, "policy does not exists", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleListIdentities(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(roles.Identities()) }
}

func HandleForgetIdentity(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			http.Error(w, "invalid identity", http.StatusBadRequest)
			return
		}
		if identity == roles.Root {
			http.Error(w, "identity is root", http.StatusBadRequest)
			return
		}
		roles.Forget(identity)
		w.WriteHeader(http.StatusOK)
	}
}

func pathBase(p string) string { return path.Base(p) }

func statusCode(err error) int {
	if err, ok := err.(interface{ Status() int }); ok {
		return err.Status()
	}
	return http.StatusInternalServerError
}

func asStatusError(err error, msg string, status int) error {
	if _, ok := err.(interface{ Status() int }); ok {
		return err
	}
	return statusError{
		msg:    fmt.Sprintf("%s: %s", msg, err.Error()),
		status: status,
	}
}

type statusError struct {
	msg    string
	status int
}

func (e statusError) Error() string { return e.msg }
func (e statusError) Status() int   { return e.status }
