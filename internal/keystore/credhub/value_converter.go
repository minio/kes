// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package credhub

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

const Base64Prefix = "Base64:"

func bytesToJsonString(bytes []byte, forceBase64 bool) (value string) {
	if utf8.Valid(bytes) && !forceBase64 {
		strBytes := string(bytes)
		if !strings.HasPrefix(strBytes, Base64Prefix) {
			return string(bytes)
		}
	}
	return Base64Prefix + base64.StdEncoding.EncodeToString(bytes)
}

func jsonStringToBytes(value string) (bytes []byte, err error) {
	if strings.HasPrefix(value, Base64Prefix) {
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(value, Base64Prefix))
	}
	return []byte(value), nil
}
