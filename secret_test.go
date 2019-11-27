package key

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/secure-io/sio-go/sioutil"
)

var secretWrapTests = []struct {
	KeyLen         int
	AssociatedData []byte
}{
	{KeyLen: 0, AssociatedData: nil},                                                // 0
	{KeyLen: 1, AssociatedData: nil},                                                // 1
	{KeyLen: 16, AssociatedData: make([]byte, 0)},                                   // 2
	{KeyLen: 32, AssociatedData: mustDecodeHex("ff")},                               // 3
	{KeyLen: 128, AssociatedData: make([]byte, 1024)},                               // 4
	{KeyLen: 1024, AssociatedData: mustDecodeHex("a2e31cb681f3")},                   // 5
	{KeyLen: 63, AssociatedData: mustDecodeHex("cb653b4c5426e0d41f5ae673ffa0f659")}, // 6
}

func TestSecretWrap(t *testing.T) {
	var secret Secret
	copy(secret[:], sioutil.MustRandom(len(secret)))

	for i, test := range secretWrapTests {
		data := make([]byte, test.KeyLen)
		ciphertext, err := secret.Wrap(data, test.AssociatedData)
		if err != nil {
			t.Logf("Test %d: Secret: %x\n", i, secret)
			t.Fatalf("Test %d: Failed to wrap data: %v", i, err)
		}
		plaintext, err := secret.Unwrap(ciphertext, test.AssociatedData)
		if err != nil {
			t.Logf("Test %d: Secret: %x\n", i, secret)
			t.Fatalf("Test %d: Failed to unwrap data: %v", i, err)
		}
		if !bytes.Equal(data, plaintext) {
			t.Logf("Test %d: Secret: %x\n", i, secret)
			t.Fatalf("Test %d: Original plaintext does not match unwrapped plaintext", i)
		}
	}
}

var secretUnwrapTests = []struct {
	Ciphertext     string
	AssociatedData []byte
	ShouldFail     bool
}{
	{ // 0
		Ciphertext:     `{"aead":"AES-256-GCM","iv":"VJVUvXnRN52Pr/eRJQYUzQ==","nonce":"C5QfVoDLfTKirjjB","bytes":"pF3/xU1e916zhTBHEdPE+E+MR5h9wFsyerjWhYIfdYA="}`,
		AssociatedData: nil,
	},
	{ // 1
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
	},
	{ // 2
		Ciphertext:     `{"aead":"AES-GCM","iv":"9Qup+RN5PQLQNxkqSsae","nonce":"C5QfVoDLfTKirjjB","bytes":"pF3/xU1e916zhTBHEdPE+E+MR5h9wFsyerjWhYIfdYA="}`,
		AssociatedData: nil,
		ShouldFail:     true, // Invalid algorithm
	},
	{ // 3
		Ciphertext:     `{"aead":"AES-256-GCM","iv":"9Qup+RN5PQLQNxkqSsae","nonce":"C5QfVoDLfTKirjjB","bytes":"pF3/xU1e916zhTBHEdPE+E+MR5h9wFsyerjWhYIfdYA="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid IV length
	},
	{ // 4
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"n9XhMi9e/KfIvIJniCoh4Q==","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
	},
	{ // 5
		Ciphertext:     `{"aead":"AES-256-GCM","iv":"VJVUvXnRN52Pr/eRJQYUzQ==","nonce":"EryghN51hWA=","bytes":"pF3/xU1e916zhTBHEdPE+E+MR5h9wFsyerjWhYIfdYA="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
	},
	{ // 6
		Ciphertext:     `{"aead":"AES-256-GCM","iv":"VJVUvXnRN52Pr/eRJQYUzQ==","nonce":"C5QfVoDLfTKirjjB","bytes":"WH19g/H1oi/eejfRXWiEyPH4QHw2NrG+Wz+HXF07MOU="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
	},
	{ // 7
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"TTi8pkO+Jh1JWAHvPxZeUk/iVoBPUCE4ZSVGBy3fW2s="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
	},
	{ // 8
		Ciphertext:     `{"aead":"AES-256-GCM" "iv":"VJVUvXnRN52Pr/eRJQYUzQ==","nonce":"C5QfVoDLfTKirjjB","bytes":"pF3/xU1e916zhTBHEdPE+E+MR5h9wFsyerjWhYIfdYA="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid JSON
	},
}

func TestSecrectUnwrap(t *testing.T) {
	var secret Secret
	Plaintext := make([]byte, 16)
	for i, test := range secretUnwrapTests {
		plaintext, err := secret.Unwrap([]byte(test.Ciphertext), test.AssociatedData)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to unwrap ciphertext: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Expected to fail but succeeded", i)
		}
		if !test.ShouldFail && !bytes.Equal(plaintext, Plaintext) {
			t.Fatalf("Test %d: Plaintext mismatch: got %x - want %x", i, plaintext, Plaintext)
		}
	}
}

var aesDeriveKeyTests = []struct {
	Key        []byte
	IV         []byte
	DerivedKey []byte
	ShouldFail bool
}{
	{
		Key:        make([]byte, 16),
		IV:         make([]byte, 16),
		DerivedKey: mustDecodeHex("66e94bd4ef8a2c3b47711816e91d6ff0"),
	},
	{
		Key:        mustDecodeHex("8f7ac5e8a42206d7c2e605914ba67498"),
		IV:         mustDecodeHex("e24e500a7359d5564fa6e5d52e6cdc30"),
		DerivedKey: mustDecodeHex("4df46cff20a8ac7cc2bcd2696ff81c58"),
	},
	{
		Key:        make([]byte, 32),
		IV:         make([]byte, 16),
		DerivedKey: mustDecodeHex("dc95c078a24089895275f3d86b4fb868779b38d15bffb63d39d6e9ae76a9b2f3"),
	},
	{
		Key:        mustDecodeHex("5b647be0a1ecb2a01d3b0223f19b454b114be28cda1bf55bd28c478980139986"),
		IV:         mustDecodeHex("325b10c6a642a992c3539554358c0b8a"),
		DerivedKey: mustDecodeHex("3ef16fe5987c5dcbc263ffea80a04eff929990116741d3311f13aab08849592c"),
	},
	{
		Key:        make([]byte, 24),
		IV:         make([]byte, 16),
		ShouldFail: true, // Invalid key size: Only AES-128 and AES-256, not AES-192
	},
	{
		Key:        make([]byte, 32),
		IV:         make([]byte, 15),
		ShouldFail: true, // Invalid IV size: len(IV) == 16
	},
}

func TestAESDeriveKey(t *testing.T) {
	for i, test := range aesDeriveKeyTests {
		key, err := aesDeriveKey(test.Key, test.IV)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to derive key: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Expected to fail but succeeded", i)
		}
		if !test.ShouldFail && !bytes.Equal(key, test.DerivedKey) {
			t.Fatalf("Test %d: Derived key mismatch: got %x - want %x", i, key, test.DerivedKey)
		}
	}
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
