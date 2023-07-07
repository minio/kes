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
	store, err := fs.NewStore(*fsPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	t.Run("Metrics", func(t *testing.T) { testMetrics(ctx, store, t) })
	t.Run("APIs", func(t *testing.T) { testAPIs(ctx, store, t) })
	t.Run("CreateKey", func(t *testing.T) { testCreateKey(ctx, store, t, RandString(ranStringLength)) })
	t.Run("ImportKey", func(t *testing.T) { testImportKey(ctx, store, t, RandString(ranStringLength)) })
	t.Run("GenerateKey", func(t *testing.T) { testGenerateKey(ctx, store, t, RandString(ranStringLength)) })
	t.Run("EncryptKey", func(t *testing.T) { testEncryptKey(ctx, store, t, RandString(ranStringLength)) })
	t.Run("DecryptKey", func(t *testing.T) { testDecryptKey(ctx, store, t, RandString(ranStringLength)) })
	t.Run("DecryptKeyAll", func(t *testing.T) { testDecryptKeyAll(ctx, store, t, RandString(ranStringLength)) })
	t.Run("DescribePolicy", func(t *testing.T) { testDescribePolicy(ctx, store, t) })
	t.Run("GetPolicy", func(t *testing.T) { testGetPolicy(ctx, store, t) })
	t.Run("SelfDescribe", func(t *testing.T) { testSelfDescribe(ctx, store, t) })
}
