package kestest_test

import (
	"flag"
	"testing"

	"github.com/minio/kes/internal/keystore/fs"
)

var fsPath = flag.String("fs.path", "", "FS Path")

func TestGatewayFS(t *testing.T) {
	if *fsPath == "" {
		t.Skip("FS tests disabled. Use -fs.path=<path> to enable them.")
	}
	var err error
	store, err = fs.NewStore(*fsPath)
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
