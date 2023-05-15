package edge_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge"
)

var fortanixConfigFile = flag.String("fortanix.config", "", "Path to a KES config file with Fortanix SecretsManager config")

func TestFortanix(t *testing.T) {
	if *fortanixConfigFile == "" {
		t.Skip("Fortanix tests disabled. Use -fortanix.config=<config file with Fortanix SecretManager config> to enable them")
	}
	file, err := os.Open(*fortanixConfigFile)
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
