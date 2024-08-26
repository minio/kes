package credhub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/minio/kes/internal/api"
	"github.com/minio/kms-go/kes"
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
func TestStore_MTLS(t *testing.T) {
	t.Run("get status request contract", func(t *testing.T) {
		t.Skip("skipping due to this being an integration test that requires specific configuration for a CredHub instance")
		client, err := newHTTPMTLSClient(&Config{
			BaseURL:                  "https://localhost:8844",
			Namespace:                testNamespace,
			EnableMutualTLS:          true,
			ClientCertFilePath:       "../../../client.cert",
			ClientKeyFilePath:        "../../../client.key",
			ServerInsecureSkipVerify: false,
			ServerCaCertFilePath:     "../../../server-ca.cert",
		})
		assertNoError(t, err)
		resp := client.doRequest(context.Background(), "GET", "/api/v1/data?path=/", nil)
		assertNoError(t, resp.err)
		fmt.Println(resp.status)
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
		const operationID = "test"
		fakeClient.respBody = fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, value, operationID)
		store.config.ForceBase64ValuesEncoding = false
		err := store.put(context.Background(), key, []byte(value), operationID)
		assertNoError(t, err)
		assertRequestWithJSONBody(t, fakeClient, "PUT", "/api/v1/data",
			fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, value, operationID))
	})

	t.Run("PUT string value with forced Base64 encoding request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		const value = "string-value"
		const encodedValue = "Base64:c3RyaW5nLXZhbHVl"
		const operationID = "test"
		store.config.ForceBase64ValuesEncoding = true
		fakeClient.respBody = fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, encodedValue, operationID)
		err := store.put(context.Background(), key, []byte(value), operationID)
		assertNoError(t, err)
		assertRequestWithJSONBody(t, fakeClient, "PUT", "/api/v1/data",
			fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, encodedValue, operationID))
	})
	t.Run("PUT bytes value with not valid UTF-8 bytes", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		value := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 80, 114, 122, 255, 121, 107, 108, 255}
		const encodedValue = "Base64:AAECAwQFBgcICQpQcnr/eWts/w=="
		const operationID = "test"
		store.config.ForceBase64ValuesEncoding = false
		fakeClient.respBody = fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, encodedValue, operationID)
		err := store.put(context.Background(), key, value, operationID)
		assertNoError(t, err)
		assertRequestWithJSONBody(t, fakeClient, "PUT", "/api/v1/data",
			fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, encodedValue, operationID))
	})
	t.Run("PUT string value starts with 'Base64:' request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		const value = "Base64:string-value"
		const encodedValue = "Base64:QmFzZTY0OnN0cmluZy12YWx1ZQ=="
		const operationID = "test"
		store.config.ForceBase64ValuesEncoding = false
		fakeClient.respBody = fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, encodedValue, operationID)
		err := store.put(context.Background(), key, []byte(value), operationID)
		assertNoError(t, err)
		assertRequestWithJSONBody(t, fakeClient, "PUT", "/api/v1/data",
			fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, encodedValue, operationID))
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
		assertAPIErrorStatus(t, err, http.StatusBadRequest)
	})
	t.Run("create element that doesn't exist", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 404
		fakeClient.respStatusCodes["PUT"] = 200
		const key = "key"
		const value = "string-value"
		const operationID = "test"
		fakeClient.respBody = fmt.Sprintf(`{"name":"%s/%s","type":"value","value":"%s","metadata":{"operation_id":"%s"}}`, testNamespace, key, value, operationID)
		err := store.create(context.Background(), key, []byte(value), operationID)
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
		encodedValue := bytesToJSONString(value, true)
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
		assertAPIErrorStatus(t, err, http.StatusNotFound)
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
		assertAPIErrorStatus(t, err, http.StatusNotFound)
	})
}

// `credhub curl -X=GET -p "/api/v1/data?name-like=/test-namespace/prefix"`
func TestStore_List(t *testing.T) {
	fakeClient, store := NewFakeStore()

	t.Run("list keys request contract", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"credentials":[]}`
		_, _, err := store.List(context.Background(), "", 1)
		assertNoError(t, err)
		assertRequest(t, fakeClient, "GET", fmt.Sprintf("/api/v1/data?name-like=%s", testNamespace+"/"))
	})

	t.Run("returns empty list", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"credentials":[]}`
		list, prefix, err := store.List(context.Background(), "prefix", 1)
		assertNoError(t, err)
		assertEqualComparable(t, 0, len(list))
		assertEqualComparable(t, "", prefix)
	})

	t.Run("returns list of two elements", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"credentials":[
			{"name":"/test-namespace/prefix-key-2"},
			{"name":"/test-namespace/prefix-key-1"},
			{"name":"/test-namespace/other-key"}
		]}`
		list, prefix, err := store.List(context.Background(), "prefix", 2)
		assertNoError(t, err)
		assertEqualComparable(t, 2, len(list))
		assertEqualComparable(t, "prefix-key-1", list[0])
		assertEqualComparable(t, "prefix-key-2", list[1])
		assertEqualComparable(t, "", prefix)
	})

	t.Run("returns limited list with continuation", func(t *testing.T) {
		fakeClient.respStatusCodes["GET"] = 200
		fakeClient.respBody = `{"credentials":[
			{"name":"/test-namespace/prefix-key-3"},
			{"name":"/test-namespace/prefix-key-1"},
			{"name":"/test-namespace/other-key"},
			{"name":"/test-namespace/prefix-key-2"}
		]}`
		list, prefix, err := store.List(context.Background(), "prefix", 2)
		assertNoError(t, err)
		assertEqualComparable(t, 2, len(list))
		assertEqualComparable(t, "prefix-key-1", list[0])
		assertEqualComparable(t, "prefix-key-2", list[1])
		assertEqualComparable(t, "prefix-key-3", prefix)
	})
}

// === tools:

func NewFakeStore() (*FakeHTTPClient, *Store) {
	fakeClient := &FakeHTTPClient{respStatusCodes: map[string]int{}}
	store := &Store{
		config: &Config{Namespace: testNamespace},
		client: fakeClient,
	}
	return fakeClient, store
}

type FakeHTTPClient struct {
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

func (c *FakeHTTPClient) doRequest(_ context.Context, method, url string, body io.Reader) httpResponse {
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
	return httpResponse{statusCode: c.respStatusCodes[method], status: c.respStatus, body: mockBody, err: c.error}
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

func assertAPIErrorStatus(t *testing.T, err error, status int) {
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

func assertRequest(t *testing.T, fc *FakeHTTPClient, method, uri string) {
	if fc.reqMethod != method {
		t.Fatalf("expected requested method '%s' but got '%s'", method, fc.reqMethod)
	}
	if fc.reqUri != uri {
		t.Fatalf("expected requested uri '%s' but got '%s'", uri, fc.reqUri)
	}
}
func assertRequestWithJSONBody(t *testing.T, fc *FakeHTTPClient, method, uri string, jsonBody string) {
	assertRequest(t, fc, method, uri)

	var gotJSON, expectedJson interface{}
	err1 := json.Unmarshal([]byte(fc.reqBody), &gotJSON)
	err2 := json.Unmarshal([]byte(jsonBody), &expectedJson)

	if err1 != nil || err2 != nil {
		t.Fatalf("jsons deserialization errors: %v, %v", err1, err2)
	}

	if !reflect.DeepEqual(gotJSON, expectedJson) {
		t.Fatalf("expected requested body '%s' but got '%s'", jsonBody, fc.reqBody)
	}
}
