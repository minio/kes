package kms

import (
	"bytes"
	"encoding/json"

	"github.com/aead/key/internal/crypto"
	"github.com/secure-io/sio-go/sioutil"
)

type Key struct {
	Name  string `json:"name"`
	Bytes []byte `json:"bytes"`
}

func (k *Key) Clone() Key {
	clone := Key{
		Name:  k.Name,
		Bytes: make([]byte, len(k.Bytes)),
	}
	copy(clone.Bytes, k.Bytes)
	return clone
}

func (k *Key) Seal(plaintext, associatedData []byte) (SealedKey, error) {
	const kdf = crypto.SHAKE256
	var algorithm = crypto.AES_256_GCM
	if !sioutil.NativeAES() {
		algorithm = crypto.ChaCha20Poly1305
	}

	iv, err := sioutil.Random(ivSize)
	if err != nil {
		return SealedKey{}, err
	}
	sealingKey := kdf.Derive(k.Bytes, algorithm.KeySize(), iv)

	cipher, err := algorithm.New(sealingKey)
	if err != nil {
		return SealedKey{}, err
	}
	nonce, err := sioutil.Random(algorithm.NonceSize())
	if err != nil {
		return SealedKey{}, err
	}
	ciphertext := cipher.Seal(nil, nonce, plaintext, associatedData)

	return SealedKey{
		kdf:       kdf.String(),
		iv:        iv,
		algorithm: algorithm.String(),
		nonce:     nonce,
		bytes:     ciphertext,
	}, nil
}

func (k *Key) Open(ciphertext SealedKey, associatedData []byte) ([]byte, error) {
	kdf, err := crypto.ParseKDF(ciphertext.kdf)
	if err != nil {
		return nil, err
	}
	if len(ciphertext.iv) != ivSize {

	}
	algorithm, err := crypto.ParseAlgorithm(ciphertext.algorithm)
	if err != nil {
		return nil, err
	}
	if len(ciphertext.nonce) != algorithm.NonceSize() {

	}

	sealingKey := kdf.Derive(k.Bytes, algorithm.KeySize(), ciphertext.iv)
	cipher, err := algorithm.New(sealingKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := cipher.Open(nil, ciphertext.nonce, ciphertext.bytes, associatedData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

const ivSize = 16

type SealedKey struct {
	kdf       string
	iv        []byte
	algorithm string
	nonce     []byte
	bytes     []byte
}

func (s SealedKey) MarshalJSON() ([]byte, error) {
	if _, err := crypto.ParseKDF(s.kdf); err != nil {

	}
	if len(s.iv) != ivSize {

	}
	algorithm, err := crypto.ParseAlgorithm(s.algorithm)
	if err != nil {

	}
	if len(s.nonce) != algorithm.NonceSize() {

	}

	type sealed struct {
		KDF       string `json:"kdf"`
		IV        []byte `json:"iv"`
		Algorithm string `json:"aead"`
		Nonce     []byte `json:"nonce"`
		Bytes     []byte `json:"bytes"`
	}
	return json.Marshal(sealed{
		KDF:       s.kdf,
		IV:        s.iv,
		Algorithm: s.algorithm,
		Nonce:     s.nonce,
		Bytes:     s.bytes,
	})
}

func (s *SealedKey) UnmarshalJSON(b []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()

	type sealed struct {
		KDF       string `json:"kdf"`
		IV        []byte `json:"iv"`
		Algorithm string `json:"aead"`
		Nonce     []byte `json:"nonce"`
		Bytes     []byte `json:"bytes"`
	}
	var sealedKey sealed
	if err := decoder.Decode(&sealedKey); err != nil {
		return err
	}
	s.kdf = sealedKey.KDF
	s.iv = sealedKey.IV
	s.algorithm = sealedKey.Algorithm
	s.nonce = sealedKey.Nonce
	s.bytes = sealedKey.Bytes

	if _, err := crypto.ParseKDF(s.kdf); err != nil {

	}
	if len(s.iv) != ivSize {

	}
	algorithm, err := crypto.ParseAlgorithm(s.algorithm)
	if err != nil {

	}
	if len(s.nonce) != algorithm.NonceSize() {

	}
	return nil
}
