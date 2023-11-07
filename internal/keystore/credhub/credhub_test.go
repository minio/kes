package credhub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/api"
	"io"
	"net/http"
	"reflect"
	"testing"
)

/** CredHub Rest API contract tests.
The following is checked:
- correctness of requests: method, url, body
- correctness of responses: status, body parsing
*/

const testNamespace = "/test-namespace"

// `curl -v --cert ./client.cert --key ./client.key --cacert ./server-ca.cert https://localhost:8844/api/v1/data?path=/`
func TestStore_MTls(t *testing.T) {
	t.Run("get status request contract", func(t *testing.T) {
		t.Skip("skipping due to this being an integration test that requires specific configuration for a CredHub instance")
		client, err := NewHttpMTlsClient(&Config{
			BaseUrl:                  "https://localhost:8844",
			Namespace:                testNamespace,
			EnableMutualTls:          true,
			ClientCertFilePath:       "../../../client.cert",
			ClientKeyFilePath:        "../../../client.key",
			ServerInsecureSkipVerify: false,
			ServerCaCertFilePath:     "../../../server-ca.cert",
		})
		assertNoError(t, err)
		resp := client.DoRequest(context.Background(), "GET", "/api/v1/data?path=/", nil)
		assertNoError(t, resp.err)
		fmt.Println(resp.Status)
	})

}

// `credhub curl -X=GET -p /health`
func TestStore_Status(t *testing.T) {
	fakeClient, store := NewFakeStore()

	t.Run("get status request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"status" : "UP"}`
		_, err := store.Status(context.Background())
		assertNoError(t, err)
		assertRequest(t, fakeClient, "GET", "/health")
	})

	t.Run("returns error for status 200 and not 'UP'", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"status" : "DOWN"}`
		_, err := store.Status(context.Background())
		assertError(t, err)
	})

	t.Run("returns error for non-200 status", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 500
		_, err := store.Status(context.Background())
		assertError(t, err)
	})
}

// `credhub curl -X=PUT -p "/api/v1/data" -d='{"name":"/test-namespace/key-1","type":"value","value":"1"}`
func TestStore_put(t *testing.T) {
	fakeClient, store := NewFakeStore()

	t.Run("PUT string value without encoding request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		const value = "string-value"
		store.config.ForceBase64ValuesEncoding = false
		err := store.put(context.Background(), key, []byte(value))
		assertNoError(t, err)
		assertRequestWithJsonBody(t, fakeClient, "PUT", "/api/v1/data",
			fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s"}`, testNamespace, key, value))
	})

	t.Run("PUT string value with forced Base64 encoding request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		const value = "string-value"
		store.config.ForceBase64ValuesEncoding = true
		err := store.put(context.Background(), key, []byte(value))
		assertNoError(t, err)
		assertRequestWithJsonBody(t, fakeClient, "PUT", "/api/v1/data",
			fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s"}`, testNamespace, key, "Base64:c3RyaW5nLXZhbHVl"))
	})
	t.Run("PUT bytes value with not valid UTF-8 bytes", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		value := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 80, 114, 122, 255, 121, 107, 108, 255}
		store.config.ForceBase64ValuesEncoding = false
		err := store.put(context.Background(), key, value)
		assertNoError(t, err)
		assertRequestWithJsonBody(t, fakeClient, "PUT", "/api/v1/data",
			fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s"}`, testNamespace, key, "Base64:AAECAwQFBgcICQpQcnr/eWts/w=="))
	})
	t.Run("PUT string value starts with 'Base64:' request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		const value = "Base64:string-value"
		store.config.ForceBase64ValuesEncoding = false
		err := store.put(context.Background(), key, []byte(value))
		assertNoError(t, err)
		assertRequestWithJsonBody(t, fakeClient, "PUT", "/api/v1/data",
			fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s"}`, testNamespace, key, "Base64:QmFzZTY0OnN0cmluZy12YWx1ZQ=="))
	})
}

func TestStore_Create(t *testing.T) {
	fakeClient, store := NewFakeStore()
	existsRespBody := `{"data":[{"value":"something"}]}`

	t.Run("create element that exists", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = existsRespBody
		const key = "key"
		const value = "string-value"
		err := store.Create(context.Background(), key, []byte(value))
		assertErrorIs(t, err, kes.ErrKeyExists)
		assertApiErrorStatus(t, err, http.StatusBadRequest)
	})
	t.Run("create element that doesn't exist", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 404
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		const value = "string-value"
		err := store.Create(context.Background(), key, []byte(value))
		assertNoError(t, err)
	})
	t.Run("create element unknown error", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = existsRespBody
		fakeClient.respStatusCodes["PUT"] = 500
		const key = "key"
		const value = "string-value"
		err := store.Create(context.Background(), key, []byte(value))
		assertError(t, err)
	})
}

func TestStore_Set(t *testing.T) {
	fakeClient, store := NewFakeStore()

	t.Run("set value of element", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		const value = "string-value"
		err := store.Set(context.Background(), key, []byte(value))
		assertNoError(t, err)
	})
	t.Run("set value of element unknown error", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 500
		const key = "key"
		const value = "string-value"
		err := store.Set(context.Background(), key, []byte(value))
		assertError(t, err)
	})
}

// `credhub curl -X=GET -p "/api/v1/data?name=/test-namespace/key-4&current=true"`
func TestStore_Get(t *testing.T) {
	fakeClient, store := NewFakeStore()

	t.Run("GET string value without encoding request contract", func(t *testing.T) {
		const key = "key"
		const value = "string-value"
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = fmt.Sprintf(`
		{
		  "data" : [ {
			"type" : "value",
			"version_created_at" : "2019-02-01T20:37:52Z",
			"id" : "2e094eda-719c-43cb-a0f5-04face0a79be",
			"name" : "%s/%s",
			"metadata" : {
			  "description" : "example metadata"
			},
			"value" : "%s"
		  } ]
		}
		`, testNamespace, key, value)
		b, err := store.Get(context.Background(), key)
		assertNoError(t, err)
		assertRequest(t, fakeClient, "GET", fmt.Sprintf("/api/v1/data?current=true&name=%s/%s", testNamespace, key))
		assertEqualComparable(t, value, string(b))
	})
	t.Run("GET bytes value with Base64 encoding request contract", func(t *testing.T) {
		const key = "key"
		value := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 80, 114, 122, 255, 121, 107, 108, 255}
		encodedValue := BytesToJsonString(value, true)
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = fmt.Sprintf(`
		{
		  "data" : [ {
			"type" : "value",
			"version_created_at" : "2019-02-01T20:37:52Z",
			"id" : "2e094eda-719c-43cb-a0f5-04face0a79be",
			"name" : "%s/%s",
			"metadata" : {
			  "description" : "example metadata"
			},
			"value" : "%s"
		  } ]
		}
		`, testNamespace, key, encodedValue)
		b, err := store.Get(context.Background(), key)
		assertNoError(t, err)
		assertRequest(t, fakeClient, "GET", fmt.Sprintf("/api/v1/data?current=true&name=%s/%s", testNamespace, key))
		assertEqualBytes(t, value, b)
	})

	t.Run("GET element that doesn't exist", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 404
		const name = "element-name"
		_, err := store.Get(context.Background(), name)
		assertErrorIs(t, err, kes.ErrKeyNotFound)
		assertApiErrorStatus(t, err, http.StatusNotFound)
	})

}

// `credhub curl -X=DELETE -p "/api/v1/data?name=/test-namespace/element-name"`
func TestStore_Delete(t *testing.T) {
	fakeClient, store := NewFakeStore()

	t.Run("DELETE element request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["DELETE"] = 200
		const name = "element-name"
		err := store.Delete(context.Background(), name)
		assertNoError(t, err)
		assertRequest(t, fakeClient, "DELETE", fmt.Sprintf("/api/v1/data?name=%s/%s", testNamespace, name))
	})

	t.Run("DELETE element that doesn't exist", func(t *testing.T) {
		fakeClient.respStatusCodes["DELETE"] = 404
		const name = "element-name"
		err := store.Delete(context.Background(), name)
		assertErrorIs(t, err, kes.ErrKeyNotFound)
		assertApiErrorStatus(t, err, http.StatusNotFound)
	})
}

// `credhub curl -X=GET -p "/api/v1/data?path=/test-namespace/"`
func TestStore_List(t *testing.T) {
	fakeClient, store := NewFakeStore()
	t.Run("list keys request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"credentials":[]}`
		_, err := store.List(context.Background())
		assertNoError(t, err)
		assertRequest(t, fakeClient, "GET", fmt.Sprintf("/api/v1/data?path=%s/", testNamespace))
	})

	t.Run("returns empty list", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"credentials":[]}`
		iter, err := store.List(context.Background())
		assertNoError(t, err)
		el, more := iter.Next()
		assertEqualComparable(t, el, "")
		assertEqualComparable(t, more, false)
	})
	t.Run("returns list of two elements", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"credentials":[{"version_created_at":"2023-10-26T14:46:14Z","name":"/test-namespace/key-1"},{"version_created_at":"2023-10-26T14:46:08Z","name":"/test-namespace/key-2"}]}`
		iter, err := store.List(context.Background())
		assertNoError(t, err)
		assertRequest(t, fakeClient, "GET", fmt.Sprintf("/api/v1/data?path=%s/", testNamespace))
		k, more := iter.Next()
		assertEqualComparable(t, k, "key-1")
		assertEqualComparable(t, more, true)
		k, more = iter.Next()
		assertEqualComparable(t, k, "key-2")
		assertEqualComparable(t, more, false)
		k, more = iter.Next()
		assertEqualComparable(t, k, "")
		assertEqualComparable(t, more, false)
	})
}

//=== tools:

func NewFakeStore() (*FakeHttpClient, *Store) {
	fakeClient := &FakeHttpClient{respStatusCodes: map[string]int{}}
	store := &Store{
		config: &Config{Namespace: testNamespace},
		client: fakeClient,
	}
	return fakeClient, store
}

type FakeHttpClient struct {
	reqMethod       string
	reqUri          string
	reqBody         string
	respStatusCodes map[string]int
	respStatus      string
	respBody        string
	error           error
}

type FakeReadCloser struct {
	io.Reader
}

func (m *FakeReadCloser) Close() error {
	return nil
}

func (c *FakeHttpClient) DoRequest(_ context.Context, method, url string, body io.Reader) HttpResponse {
	c.reqMethod = method
	c.reqUri = url
	c.reqBody = ""
	if body != nil {
		bodyBytes, err := io.ReadAll(body)
		if err == nil {
			c.reqBody = string(bodyBytes)
		}
	}
	mockBody := &FakeReadCloser{
		Reader: bytes.NewBufferString(c.respBody),
	}
	return HttpResponse{StatusCode: c.respStatusCodes[method], Status: c.respStatus, Body: mockBody, err: c.error}
}

func assertError(t *testing.T, err error) {
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func assertErrorIs(t *testing.T, err, target error) {
	if err == nil || target == nil {
		t.Fatal("error can't be null")
	}
	if !errors.Is(err, target) {
		t.Fatal(fmt.Sprintf("error '%v' isn't '%v'", err, target))
	}
}

func assertApiErrorStatus(t *testing.T, err error, status int) {
	if err == nil {
		t.Fatal("error can't be null")
	}
	apiErr, isIt := api.IsError(err)
	if !isIt {
		t.Fatal(fmt.Sprintf("error '%+v' isn't api error '%+v'", err, apiErr))
	}
	if apiErr.Status() != status {
		t.Fatal(fmt.Sprintf("expect error status '%d', got '%d'", status, apiErr.Status()))
	}
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func assertEqualComparable(t *testing.T, expected, got any) {
	if expected != got {
		t.Fatalf("expected '%v' got '%v'", expected, got)
	}
}
func assertEqualBytes(t *testing.T, expected, got []byte) {
	if !bytes.Equal(expected, got) {
		t.Fatalf("expected '%v' got '%v'", expected, got)
	}
}

func assertRequest(t *testing.T, fc *FakeHttpClient, method, uri string) {
	if fc.reqMethod != method {
		t.Fatalf("expected requested method '%s' but got '%s'", method, fc.reqMethod)
	}
	if fc.reqUri != uri {
		t.Fatalf("expected requested uri '%s' but got '%s'", uri, fc.reqUri)
	}
}
func assertRequestWithJsonBody(t *testing.T, fc *FakeHttpClient, method, uri string, jsonBody string) {
	assertRequest(t, fc, method, uri)

	var gotJson, expectedJson interface{}
	err1 := json.Unmarshal([]byte(fc.reqBody), &gotJson)
	err2 := json.Unmarshal([]byte(jsonBody), &expectedJson)

	if err1 != nil || err2 != nil {
		t.Fatalf("jsons deserialization errors: %v, %v", err1, err2)
	}

	if !reflect.DeepEqual(gotJson, expectedJson) {
		t.Fatalf("expected requested body '%s' but got '%s'", jsonBody, fc.reqBody)
	}
}
