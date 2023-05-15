package edge_test

import (
	"context"
	"flag"
	"testing"

	"github.com/minio/kes/edge"
)

var FSPath = flag.String("fs.path", "", "Path used for FS tests")

func TestFS(t *testing.T) {
	if *FSPath == "" {
		t.Skip("FS tests disabled. Use -fs.path=<path> to enable them")
	}
	config := edge.FSKeyStore{
		Path: *FSPath,
	}

	var err error
	store, err = config.Connect(context.Background())
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
