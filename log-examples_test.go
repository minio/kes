// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes_test

import (
	"fmt"
	"strings"

	"github.com/minio/kes"
)

const AuditStream = `{"time":"2020-03-24T12:37:33Z","request":{"path":"/v1/log/audit/trace","identity":"dd46485bedc9ad2909d2e8f9017216eec4413bc5c64b236d992f7ec19c843c5f"},"response":{"code":200, "time":12106}}
{"time":"2020-03-24T12:38:02Z","request":{"path":"/v1/policy/list/*","identity":"dd46485bedc9ad2909d2e8f9017216eec4413bc5c64b236d992f7ec19c843c5f"},"response":{"code":200, "time":15572}}
{"time":"2020-03-24T12:39:02Z","request":{"path":"/v1/identity/list/*","identity":"dd46485bedc9ad2909d2e8f9017216eec4413bc5c64b236d992f7ec19c843c5f"},"response":{"code":200, "time":15953}}`

func ExampleNewAuditStream() {
	reader := strings.NewReader(AuditStream)

	stream := kes.NewAuditStream(reader)
	for stream.Next() {
		event := stream.Event()

		fmt.Println(event.Time)
	}
	if err := stream.Err(); err != nil {
		panic(err) // TODO: error handling
	}
	// Output:
	// 2020-03-24 12:37:33 +0000 UTC
	// 2020-03-24 12:38:02 +0000 UTC
	// 2020-03-24 12:39:02 +0000 UTC
}

const ErrorStream = `{"message":"2020/03/24 14:46:10 aws: secret was not encrypted with '4f9147d9-a676-47cd-ad3f-3485abf9123d'"}
{"message":"2020/03/24 14:46:17 aws: the CMK 'ff8e2c25-b259-4f74-a001-c7b62d17e0a4' does not exist"}
{"message":"2020/03/24 14:46:25 aws: the CMK '8fc17745-9647-4797-b170-afd8b52ed7c0' cannot be used for decryption"}`

func ExampleNewErrorStream() {
	reader := strings.NewReader(ErrorStream)

	stream := kes.NewErrorStream(reader)
	for stream.Next() {
		event := stream.Event()

		fmt.Println(event.Message)
	}
	if err := stream.Err(); err != nil {
		panic(err) // TODO: error handling
	}
	// Output:
	// 2020/03/24 14:46:10 aws: secret was not encrypted with '4f9147d9-a676-47cd-ad3f-3485abf9123d'
	// 2020/03/24 14:46:17 aws: the CMK 'ff8e2c25-b259-4f74-a001-c7b62d17e0a4' does not exist
	// 2020/03/24 14:46:25 aws: the CMK '8fc17745-9647-4797-b170-afd8b52ed7c0' cannot be used for decryption
}
