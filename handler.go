package key

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/aead/key/internal/xhttp"
	"github.com/aead/key/kms"
	"github.com/secure-io/sio-go/sioutil"
)

type createKeyRequest struct {
	Bytes []byte `json:"bytes"` // Optional
}

func createKeyHandler(store kms.KeyStore) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req createKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return xhttp.AsError(err, http.StatusBadRequest, "invalid JSON")
		}
		key := kms.Key{
			Name:  path.Base(r.URL.Path),
			Bytes: req.Bytes,
		}
		if len(key.Bytes) == 0 {
			var err error
			key.Bytes, err = sioutil.Random(32)
			if err != nil {
				return err
			}
		}
		return store.Create(key)
	}
}

func deleteKeyHandler(store kms.KeyStore) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		return store.Delete(path.Base(r.URL.Path))
	}
}

type generateKeyRequest struct {
	Context []byte `json:"context"` // Optional
}

type generateKeyResponse struct {
	Plaintext  []byte `json:"plaintext"`
	Ciphertext []byte `json:"ciphertext"`
}

func generateKeyHandler(store kms.KeyStore) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req generateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return xhttp.AsError(err, http.StatusBadRequest, "invalid JSON")
		}

		name := path.Base(r.URL.Path)
		key, err := store.Get(name)
		if err != nil {
			return xhttp.AsError(err, http.StatusNotFound, fmt.Sprintf("%s not found", name))
		}

		dataKey, err := sioutil.Random(32)
		if err != nil {
			return err
		}

		sealedKey, err := key.Seal(dataKey, req.Context)
		if err != nil {
			return err
		}
		ciphertext, err := json.Marshal(sealedKey)
		if err != nil {
			return err
		}

		json.NewEncoder(w).Encode(generateKeyResponse{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
		})
		return nil
	}
}

type decryptKeyRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context"`
}

type decryptKeyResponse struct {
	Plaintext []byte `json:"plaintext"`
}

func decryptKeyHandler(store kms.KeyStore) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req decryptKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return xhttp.AsError(err, http.StatusBadRequest, "invalid JSON")
		}

		name := path.Base(r.URL.Path)
		key, err := store.Get(name)
		if err != nil {
			return xhttp.AsError(err, http.StatusNotFound, fmt.Sprintf("%s not found", name))
		}

		var sealedKey kms.SealedKey
		if err := json.Unmarshal(req.Ciphertext, &sealedKey); err != nil {
			return xhttp.AsError(err, http.StatusBadRequest, "invalid ciphertext")
		}
		plaintext, err := key.Open(sealedKey, req.Context)
		if err != nil {
			return err
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(decryptKeyResponse{
			Plaintext: plaintext,
		})
		return nil
	}
}

func writePolicyHandler(roles *Roles) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var policy Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			return xhttp.AsError(err, http.StatusBadRequest, "invalid JSON")
		}
		roles.Set(path.Base(r.URL.Path), &policy)
		return nil
	}
}

func readPolicyHandler(roles *Roles) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		policy, ok := roles.Get(path.Base(r.URL.Path))
		if !ok {
			return xhttp.Error(http.StatusNotFound, "policy does not exists")
		}
		json.NewEncoder(w).Encode(policy)
		return nil
	}
}

func listPoliciesHandler(roles *Roles) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(roles.List())
		return nil
	}
}

func deletePolicyHandler(roles *Roles) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		roles.Delete(path.Base(r.URL.Path))
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

type assignIdentityRequest struct {
	Policy string `json:"policy"`
}

func assignIdentityHandler(roles *Roles) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req assignIdentityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return xhttp.AsError(err, http.StatusBadRequest, "invalid JSON")
		}

		identity := Identity(path.Base(r.URL.Path))
		if identity == roles.Root {
			return xhttp.Error(http.StatusBadRequest, "identity is root")
		}
		if err := roles.Assign(req.Policy, identity); err != nil {
			return xhttp.Error(http.StatusNotFound, fmt.Sprintf("policy '%s' does not exists", req.Policy))
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

func listIdentitiesHandler(roles *Roles) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		json.NewEncoder(w).Encode(roles.ListIdentities())
		return nil
	}
}

func forgetIdentityHandler(roles *Roles) xhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		identity := Identity(path.Base(r.URL.Path))
		if identity == roles.Root {
			return xhttp.Error(http.StatusBadRequest, "identity is root")
		}
		roles.Forget(identity)
		w.WriteHeader(http.StatusOK)
		return nil
	}
}
