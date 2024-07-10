package token

import (
	"context"
	"io"
	"time"
)

type Store interface {
	io.Closer
	Get(ctx context.Context, tokenID string) ([]byte, error)
	Put(ctx context.Context, tokenID string, token []byte, ttl time.Duration) error
	Delete(ctx context.Context, tokenID string) error
}
