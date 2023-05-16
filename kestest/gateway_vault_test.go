package kestest_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge"
)

var vaultConfigFile = flag.String("vault.config", "", "Path to a KES config file with Vault SecretsManager config")

func TestGatewayVault(t *testing.T) {
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
