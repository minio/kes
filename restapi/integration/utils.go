package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

var (
	client     = &http.Client{Timeout: 2 * time.Second}
	cookieName = "kes-ui-token"
)

func login() (string, error) {
	keyPath := "../../client.key"
	certPath := "../../client.crt"
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	keyFile, err := os.Open(keyPath)
	if err != nil {
		return "", err
	}

	w, err := writer.CreateFormFile("key", keyPath)
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(w, keyFile); err != nil {
		return "", err
	}

	certFile, err := os.Open(certPath)
	if err != nil {
		return "", err
	}

	w, err = writer.CreateFormFile("cert", certPath)
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(w, certFile); err != nil {
		return "", err
	}
	insecure, _ := writer.CreateFormField("insecure")
	insecure.Write([]byte("true"))

	writer.Close()

	request, err := http.NewRequest("POST", "http://localhost:9393/api/v1/login", body)
	request.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		return "", err
	}

	response, err := client.Do(request)
	if err != nil {
		return "", err
	}

	if response != nil {
		for _, cookie := range response.Cookies() {
			if cookie.Name == cookieName {
				return cookie.Value, nil
			}
		}
	}
	return "", errors.New("no token found")
}

func makeRequest(data map[string]interface{}, method, url, token string) (*http.Response, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	body := bytes.NewReader(jsonData)
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Cookie", fmt.Sprintf("%s=%s", cookieName, token))
	request.Header.Add("Content-Type", "application/json")
	return client.Do(request)
}
