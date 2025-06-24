// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package credhub

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

const base64Prefix = "Base64:"

func bytesToJSONString(bytes []byte, forceBase64 bool) (value string) {
	if utf8.Valid(bytes) && !forceBase64 {
		strBytes := string(bytes)
		if !strings.HasPrefix(strBytes, base64Prefix) {
			return string(bytes)
		}
	}
	return base64Prefix + base64.StdEncoding.EncodeToString(bytes)
}

func jsonStringToBytes(value string) (bytes []byte, err error) {
	if strings.HasPrefix(value, base64Prefix) {
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(value, base64Prefix))
	}
	return []byte(value), nil
}
