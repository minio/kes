package crypto

import (
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

const SHAKE256 kdf = "SHAKE-256"

type kdf string

func (f kdf) New(key []byte) sha3.ShakeHash {
	switch f {
	case SHAKE256:
		h := sha3.NewShake256()
		h.Write(key)
		return h
	default:
		panic(fmt.Sprintf("internal/crypto: unkown KDF '%s'", f))
	}
}

func (f kdf) Derive(key []byte, size int, random []byte) []byte {
	v := make([]byte, size)

	h := f.New(key)
	h.Write(random)
	if _, err := io.ReadFull(h, v); err != nil {
		panic(fmt.Sprintf("internal/crypto: failed to read from KDF: %v", err))
	}
	return v
}

func (f kdf) String() string { return string(f) }

func ParseKDF(s string) (kdf, error) {
	switch s {
	case SHAKE256.String():
		return SHAKE256, nil
	default:
		return "", fmt.Errorf("internal/crypto: unknown KDF '%s'", s)
	}
}
