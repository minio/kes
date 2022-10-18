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
