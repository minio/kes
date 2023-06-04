package kes_test

import (
	"context"
	"fmt"
	"log"

	"github.com/minio/kes"
)

func ExampleParseAddr() {
	addr, err := kes.ParseAddr("127.0.0.1:7373")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(addr.Host())
	fmt.Println(addr.String())
	fmt.Println(addr.URL())
	fmt.Println(addr.URL("v1", "status"))

	// Output:
	// 127.0.0.1
	// 127.0.0.1:7373
	// https://127.0.0.1:7373
	// https://127.0.0.1:7373/v1/status
}

func ExampleAddr_Equal() {
	addr0, _ := kes.ParseAddr("127.0.0.1:7373")
	addr1, _ := kes.ParseAddr("https://localhost:7373")
	addr2, _ := kes.ParseAddr("example.com:7373")

	if addr0.Equal(addr1) {
		fmt.Println(addr0, "==", addr1)
	}
	if !addr0.Equal(addr2) {
		fmt.Println(addr0, "!=", addr2)
	}

	// Output:
	// 127.0.0.1:7373 == localhost:7373
	// 127.0.0.1:7373 != example.com:7373
}

func ExampleParseSoftHSM() {
	const key = "kes:v1:aes256:xVPTWGcEMj7PRIWJ8Hr8uxmdf/NUrCyXthNeSvU9t+o="

	hsm, err := kes.ParseSoftHSM(key)
	if err != nil {
		log.Fatal(err)
	}
	apiKey, err := hsm.APIKey(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(apiKey.String())
	fmt.Println(apiKey.Identity())

	// Output:
	// kes:v1:ABCpPQFHycJp0TEBEalMHsyrkE/FTHHk4Jqsl7Az7MlF
	// 144353570a5ec16b42c8b4e446bb98dce0bc0a84c0996084da878f4e6379b582
}
