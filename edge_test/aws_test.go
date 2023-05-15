package edge_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge"
)

var awsConfigFile = flag.String("aws.config", "", "Path to a KES config file with AWS SecretsManager config")

func TestAWS(t *testing.T) {
	if *awsConfigFile == "" {
		t.Skip("AWS tests disabled. Use -aws.config=<config file with AWS SecretManager config> to enable them")
	}

	file, err := os.Open(*awsConfigFile)
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
