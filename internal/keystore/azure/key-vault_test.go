// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

var (
	prefix  = fmt.Sprintf("%04d-", rand.Intn(10000))
	keyName = fmt.Sprintf("%skey", prefix)
)

func TestConnectWithCredentials(t *testing.T) {
	EndPoint := os.Getenv("EndPoint")
	if EndPoint == "" {
		t.Skip("Skipping test due to missing Keyvault endpoint")
	}

	c, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		t.Fatalf("unable to determine Azure credentials: %v", err)
	}

	c1, err := ConnectWithCredentials(EndPoint, c)
	if err != nil {
		return
	}

	ctx := context.Background()

	// create key
	keyValue := time.Now().Format(time.RFC3339Nano)
	err = c1.Create(ctx, keyName, []byte(keyValue))
	if err != nil {
		t.Error(err)
	}

	// delete key upon termination
	defer c1.Delete(ctx, keyName)

	// fetch key and check if the value is correct
	data, err := c1.Get(ctx, keyName)
	if err != nil {
		t.Errorf("Error fetching key: %v", err)
	}
	if string(data) != keyValue {
		t.Errorf("Got %q, but expected %q", string(data), keyValue)
	}

	// list keys
	list, next, err := c1.List(ctx, prefix, 25)
	if err != nil {
		t.Errorf("Error listing keys: %v", err)
	}
	if len(list) != 1 || next != "" {
		t.Log("Got the following keys:\n")
		for _, key := range list {
			t.Logf("- %s", key)
			t.Errorf("Got %d keys, but expected 1 key", len(list))
		}
	}

	// delete the key
	err = c1.Delete(ctx, keyName)
	if err != nil {
		t.Errorf("Error deleting key: %v", err)
	}

	// recreate the key (deleted secret should be purged automatically)
	keyValue = time.Now().Format(time.RFC3339Nano)
	err = c1.Create(ctx, keyName, []byte(keyValue))
	if err != nil {
		t.Error(err)
	}

	// fetch key and check if the value is correct
	data, err = c1.Get(ctx, keyName)
	if err != nil {
		t.Errorf("Error fetching key: %v", err)
	}
	if string(data) != keyValue {
		t.Errorf("Got %q, but expected %q", string(data), keyValue)
	}
}
