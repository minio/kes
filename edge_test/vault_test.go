package edge_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge"
)

var vaultConfigFile = flag.String("vault.config", "", "Path to a KES config file with Vault SecretsManager config")

func TestVault(t *testing.T) {
	if *vaultConfigFile == "" {
		t.Skip("Vault tests disabled. Use -vault.config=<config file with Vault SecretManager config> to enable them")
	}
	file, err := os.Open(*vaultConfigFile)
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
