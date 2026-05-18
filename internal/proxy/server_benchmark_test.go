package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

func BenchmarkRelay(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 32*1024)
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		client, proxyClient := net.Pipe()
		target, proxyTarget := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- relay(ctx, proxyClient, proxyTarget, bytes.NewReader(payload)) }()

		readDone := make(chan error, 1)
		go func() {
			_, err := io.CopyN(io.Discard, target, int64(len(payload)))
			readDone <- err
			_ = target.Close()
		}()

		if err := <-readDone; err != nil {
			b.Fatalf("relay target read: %v", err)
		}
		_ = client.Close()
		if err := <-done; err != nil {
			cancel()
			b.Fatalf("relay returned error: %v", err)
		}
		cancel()
	}
}
