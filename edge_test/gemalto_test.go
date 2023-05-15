package edge_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge"
)

var gemaltoConfigFile = flag.String("gemalto.config", "", "Path to a KES config file with Gemalto SecretsManager config")

func TestGemalto(t *testing.T) {
	if *gemaltoConfigFile == "" {
		t.Skip("Gemalto tests disabled. Use -gemalto.config=<config file with Gemalto SecretManager config> to enable them")
	}
	file, err := os.Open(*gemaltoConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	srvrConfig, err := edge.ReadServerConfigYAML(file)
	if err != nil {
		t.Fatal(err)
	}

	store, err = srvrConfig.KeyStore.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("create", TestCreate)
	t.Run("set", TestSet)
	t.Run("get", TestGet)
	t.Run("list", TestList)
	t.Run("delete", TestDelete)
	t.Run("status", TestStatus)
}
