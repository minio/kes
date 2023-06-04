package keystore

import (
	"context"
	"time"
)

type Conn interface {
	Status(context.Context) (State, error)

	Create(context.Context, string, []byte) error

	Get(context.Context, string) ([]byte, error)

	Delete(context.Context, string) error

	List(context.Context, string, int) ([]string, string, error)
}

type State struct {
	Latency time.Duration
}
