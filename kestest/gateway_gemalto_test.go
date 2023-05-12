package kestest_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge"
)

var gemaltoConfigFile = flag.String("gemalto.config", "", "Path to a KES config file with Gemalto SecretsManager config")

func TestGatewayGemalto(t *testing.T) {
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

	t.Run("metrics", TestMetrics)
	t.Run("apis", TestAPIs)
	t.Run("createkey", TestCreateKey)
	t.Run("importkey", TestImportKey)
	t.Run("generatekey", TestGenerateKey)
	t.Run("encryptket", TestEncryptKey)
	t.Run("decryptkey", TestDecryptKey)
	t.Run("decryptkeyall", TestDecryptKeyAll)
	t.Run("describepolicy", TestDescribePolicy)
	t.Run("getpolicy", TestGetPolicy)
	t.Run("selfdescribe", TestSelfDescribe)
}
