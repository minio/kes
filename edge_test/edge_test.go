package edge_test

import (
	"context"
	"testing"

	"github.com/minio/kes/internal/keystore/mem"
	"github.com/minio/kes/kv"
)

var store = kv.Store[string, []byte](&mem.Store{})

func TestCreate(t *testing.T) {
	if err := store.Create(context.Background(), "testkey", []byte("testvalue")); err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	value, err := store.Get(context.Background(), "testkey")
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "testvalue" {
		t.Fatal("The key vaule not matching")
	}
	_ = store.Delete(context.Background(), "testkey")
}

func TestSet(t *testing.T) {
	if err := store.Set(context.Background(), "testkey1", []byte("testvalue1")); err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}
	value, err := store.Get(context.Background(), "testkey1")
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "testvalue1" {
		t.Fatal("The key vaule not matching")
	}
	_ = store.Delete(context.Background(), "testkey1")
}

func TestGet(t *testing.T) {
	if err := store.Create(context.Background(), "testkey", []byte("testvalue")); err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	value, err := store.Get(context.Background(), "testkey")
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "testvalue" {
		t.Fatal("The key vaule not matching")
	}
	_ = store.Delete(context.Background(), "testkey")
}

func TestList(t *testing.T) {
	if err := store.Create(context.Background(), "testkey", []byte("testvalue")); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), "testkey1", []byte("testvalue1")); err != nil {
		t.Fatal(err)
	}
	iter, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for {
		key, ok := iter.Next()
		if ok {
			keys = append(keys, key)
		} else {
			break
		}
	}
	if len(keys) != 2 {
		t.Fatal("Incorrect no of keys found")
	}
	_ = store.Delete(context.Background(), "testkey")
	_ = store.Delete(context.Background(), "testkey1")
}

func TestDelete(t *testing.T) {
	if err := store.Create(context.Background(), "testkey", []byte("testvalue")); err != nil {
		t.Fatal(err)
	}

	iter, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for {
		key, ok := iter.Next()
		if ok {
			keys = append(keys, key)
		} else {
			break
		}
	}
	if len(keys) != 1 {
		t.Fatal("Incorrect no of keys found")
	}

	if err := store.Delete(context.Background(), "testkey"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "testkey"); err != nil {
		t.Log("Key not present anymore")
	}
}

func TestStatus(t *testing.T) {
	_, err := store.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}
