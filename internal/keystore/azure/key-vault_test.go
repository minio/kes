// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"context"
	"os"
	"testing"
)

func TestConnectWithCredentials(t *testing.T) {
	// endpoint
	EndPoint := os.Getenv("EndPoint")
	// default credential
	ClientID := os.Getenv("ClientID")
	TenantID := os.Getenv("TenantID")
	Secret := os.Getenv("Secret")
	if ClientID == "" || TenantID == "" || Secret == "" || EndPoint == "" {
		t.Skip("Skipping test due to missing credentials")
	}
	ctx := context.Background()
	c1, err := ConnectWithCredentials(ctx, EndPoint, Credentials{TenantID: TenantID, ClientID: ClientID, Secret: Secret})
	if err != nil {
		return
	}
	{
		// delete first
		_ = c1.Delete(ctx, "mytestFirst-c1")
		// create
		err = c1.Create(ctx, "mytestFirst-c1", []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		data, err := c1.Get(ctx, "mytestFirst-c1")
		t.Logf("data:[%s] err:[%v]\n", data, err)

		list, s, err := c1.List(ctx, "", 25)
		t.Logf("list:[%s] s:[%s] err:[%v]\n", list, s, err)
		t.Log("-------------------------------")
	}
	_ = c1
}

func TestConnectWithManagedIdentityCredentials(t *testing.T) {
	// endpoint
	EndPoint := os.Getenv("EndPoint")
	// managed identity credential
	ManagedIdentityClientID := os.Getenv("ManagedIdentityClientID")
	if ManagedIdentityClientID == "" || EndPoint == "" {
		t.Skip("Skipping test due to missing credentials")
	}
	ctx := context.Background()
	c1, err := ConnectWithIdentity(ctx, EndPoint, ManagedIdentity{ClientID: ManagedIdentityClientID})
	if err != nil {
		return
	}
	{
		// delete first
		_ = c1.Delete(ctx, "mytestFirst-c1-m")
		// create
		err = c1.Create(ctx, "mytestFirst-c1-m", []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		data, err := c1.Get(ctx, "mytestFirst-c1-m")
		t.Logf("data:[%s] err:[%v]\n", data, err)

		list, s, err := c1.List(ctx, "", 25)
		t.Logf("list:[%s] s:[%s] err:[%v]\n", list, s, err)
		t.Log("-------------------------------")
	}
	_ = c1
}
