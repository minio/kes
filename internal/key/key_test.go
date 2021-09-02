package key

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/minio/kes"
	"github.com/secure-io/sio-go/sioutil"
)

var keyStringTests = []struct {
	Key    Key
	String string
}{
	{Key: Key{}, String: `{"bytes":""}`},
	{Key: mustDecodeKey("0000000000000000000000000000000000000000000000000000000000000001"), String: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="}`},
	{Key: mustDecodeKey("27caa63b2115d9c7b6ca8002fb9b7463b0923ff853329a4bed71e9027c9cfb41"), String: `{"bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="}`},
}

func TestKeyString(t *testing.T) {
	for i, test := range keyStringTests {
		if s := test.Key.String(); s != test.String {
			t.Fatalf("Test %d: got %s - want %s", i, s, test.String)
		}
	}
}

var parseTests = []struct {
	Key        Key
	String     string
	ShouldFail bool
}{
	{Key: New(make([]byte, 32)), String: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`},
	{Key: mustDecodeKey("0000000000000000000000000000000000000000000000000000000000000001"), String: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="}`},
	{Key: mustDecodeKey("27caa63b2115d9c7b6ca8002fb9b7463b0923ff853329a4bed71e9027c9cfb41"), String: `{"bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="}`},
	{String: `"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing: {
	{String: `{bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing first: "
	{String: `{"bytes""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing: :
	{String: `"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, ShouldFail: true},  // Missing final }
}

func TestParse(t *testing.T) {
	for i, test := range parseTests {
		key, err := Parse(test.String)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to parse string: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Parsing should have failed but it succeeded", i)
		}
		if err == nil && !key.Equal(test.Key) {
			t.Fatalf("Test %d: got %x - want %x", i, key.bytes, test.Key.bytes)
		}
	}
}

var keyWrapTests = []struct {
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

func TestKeyWrap(t *testing.T) {
	key := New(sioutil.MustRandom(256 / 8))
	for i, test := range keyWrapTests {
		data := make([]byte, test.KeyLen)
		ciphertext, err := key.Wrap(data, test.AssociatedData)
		if err != nil {
			t.Logf("Test %d: Secret: %x\n", i, key.bytes)
			t.Fatalf("Test %d: Failed to wrap data: %v", i, err)
		}
		plaintext, err := key.Unwrap(ciphertext, test.AssociatedData)
		if err != nil {
			t.Logf("Test %d: Secret: %x\n", i, key.bytes)
			t.Fatalf("Test %d: Failed to unwrap data: %v", i, err)
		}
		if !bytes.Equal(data, plaintext) {
			t.Logf("Test %d: Secret: %x\n", i, key.bytes)
			t.Fatalf("Test %d: Original plaintext does not match unwrapped plaintext", i)
		}
	}
}

var keyUnwrapTests = []struct {
	Ciphertext     string
	AssociatedData []byte
	ShouldFail     bool
	Err            error
}{
	{ // 0
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
	},
	{ // 1
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
	},
	{ // 2
		Ciphertext:     `{"aead":"ChaCha20Poly1305","id":"66687aadf862bd776c8fc18b8e9f8e20","iv":"EC0eZp7Pqt+LnkOae5xaAg==","nonce":"X1ejXKmH/ugFZPkk","bytes":"wIGBTDs6aOvsqJfekZ0PYRT/OHyFX2TXqeNwl1SLXOI="}`,
		AssociatedData: nil,
	},
	{ // 3
		Ciphertext:     `{"aead":"AES-256-GCM","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // Invalid algorithm
		Err:            kes.NewError(http.StatusUnprocessableEntity, "unsupported cryptographic algorithm"),
	},
	{ // 4
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"EjOY4JKqjIrPmQ5z1KSR8zlhggY=","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid IV length
		Err:            kes.NewError(http.StatusBadRequest, "invalid iv size"),
	},
	{ // 5
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"SXAbms731/c=","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
		Err:            kes.NewError(http.StatusBadRequest, "invalid nonce size"),
	},
	{ // 6
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"efY+4kYF9n8=","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
		Err:            kes.NewError(http.StatusBadRequest, "invalid nonce size"),
	},
	{ // 7
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"QTza1g5oX3f9cGJMbY1xJwWPj1F7R2VnNl6XpFKYQy0="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
		Err:            kes.ErrDecrypt,
	},
	{ // 8
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"TTi8pkO+Jh1JWAHvPxZeUk/iVoBPUCE4ZSVGBy3fW2s="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
		Err:            kes.ErrDecrypt,
	},
	{ // 9
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256" "iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid JSON
		Err:            kes.NewError(http.StatusBadRequest, "invalid ciphertext"),
	},
	{ // 10
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256", "id":"00010203040506070809101112131415", "iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid key ID
		Err:            kes.NewError(http.StatusBadRequest, "invalid ciphertext: key ID mismatch"),
	},
}

func TestKeyUnwrap(t *testing.T) {
	key := New(make([]byte, 32))
	Plaintext := make([]byte, 16)
	for i, test := range keyUnwrapTests {
		plaintext, err := key.Unwrap([]byte(test.Ciphertext), test.AssociatedData)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to unwrap ciphertext: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Expected to fail but succeeded", i)
		}
		if test.ShouldFail && err != test.Err {
			t.Fatalf("Test %d: Invalid error response: got %v - want %v", i, err, test.Err)
		}
		if !test.ShouldFail && !bytes.Equal(plaintext, Plaintext) {
			t.Fatalf("Test %d: Plaintext mismatch: got %x - want %x", i, plaintext, Plaintext)
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

func mustDecodeKey(s string) Key { return New(mustDecodeHex(s)) }
