package edge

import (
	"time"

	"github.com/minio/kes"
)

type State struct {
	Addr kes.Addr

	StartTime time.Time
}
