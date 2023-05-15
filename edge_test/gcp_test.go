package edge_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge"
)

var gcpConfigFile = flag.String("gcp.config", "", "Path to a KES config file with GCP SecretsManager config")

func TestGCP(t *testing.T) {
	if *gcpConfigFile == "" {
		t.Skip("GCP tests disabled. Use -gcp.config=<config file with GCP SecretManager config> to enable them")
	}
	file, err := os.Open(*gcpConfigFile)
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
