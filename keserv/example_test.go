// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keserv

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func ExampleEnv() {
	const Text = `{"addr":"${SERVER_ADDR}"}`

	os.Setenv("SERVER_ADDR", "127.0.0.1:7373")

	type Config struct {
		Addr Env[string] `json:"addr"`
	}
	var config Config
	if err := json.Unmarshal([]byte(Text), &config); err != nil {
		log.Fatalln(err)
	}
	fmt.Println(config.Addr.Name, "=", config.Addr.Value)
	// Output: SERVER_ADDR = 127.0.0.1:7373
}
