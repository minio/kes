// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package log

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/minio/kes"
)

var jsonWriterWriteTests = []struct {
	Content string
	Output  string
}{
	{
		Content: "",
		Output:  "{\"message\":\"\"}",
	},
	{
		Content: "\n",
		Output:  "{\"message\":\"\"}\n",
	},
	{
		Content: "Hello World",
		Output:  `{"message":"Hello World"}`,
	},
	{
		Content: "Hello \n World",
		Output:  `{"message":"Hello \n World"}`,
	},
	{
		Content: "Hello \n World" + "\n",
		Output:  `{"message":"Hello \n World"}` + "\n",
	},
	{
		Content: "Hello \t World \r" + "\n",
		Output:  `{"message":"Hello \t World \r"}` + "\n",
	},
}

func TestJSONWriterWrite(t *testing.T) {
	for i, test := range jsonWriterWriteTests {
		var buffer strings.Builder
		w := NewJSONWriter(&buffer)
		w.WriteString(test.Content)

		output := buffer.String()
		if output != test.Output {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, output, test.Output)
		}

		// Apart from testing that the JSONWriter produces expected output
		// we also test that the output can be unmarshaled to an ErrorEvent.
		// This ensures that the JSONWriter actually implements JSON marshaling
		// of the ErrorEvent type.

		newline := strings.HasSuffix(output, "\n")
		if newline {
			output = output[:len(output)-1]
		}
		var event kes.ErrorEvent
		if err := json.Unmarshal([]byte(output), &event); err != nil {
			t.Fatalf("Test %d: failed to unmarshal error event: %v", i, err)
		}
		if newline {
			event.Message += "\n"
		}
		if event.Message != test.Content {
			t.Fatalf("Test %d: error event unmarshal mismatch: got '%s' - want '%s'", i, event.Message, test.Content)
		}
	}
}
