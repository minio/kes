package edge_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge"
)

var azureConfigFile = flag.String("azure.config", "", "Path to a KES config file with Azure SecretsManager config")

func TestAzure(t *testing.T) {
	if *azureConfigFile == "" {
		t.Skip("Azure tests disabled. Use -azure.config=<config file with Azure SecretManager config> to enable them")
	}
	file, err := os.Open(*azureConfigFile)
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
