package gserver

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
)

// benchmarkGrpcWebResponse measures the cost of writing a single 1 KB payload
// through a grpcWebResponse with the given content type while the client
// advertises gzip support. It exercises the typical call pattern used by the
// handler: create writer, stream request, then finish the request.
func benchmarkGrpcWebResponse(b *testing.B, contentType string) {
	payload := bytes.Repeat([]byte("x"), 1024) // 1 KB

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp := httptest.NewRecorder()
		g := newGrpcWebResponse(resp, contentType, header.Gzip)

		// Simulate a unary response: single write followed by finish.
		_, _ = g.Write(payload)
		g.finishRequest()
	}
}

func BenchmarkGrpcWebResponse_Proto_Gzip(b *testing.B) {
	benchmarkGrpcWebResponse(b, header.ApplicationGRPCWebProto)
}

func BenchmarkGrpcWebResponse_Text_Gzip(b *testing.B) {
	benchmarkGrpcWebResponse(b, header.ApplicationGRPCWebText)
}

func benchmarkGrpcWebResponseStreaming(b *testing.B, contentType string) {
	chunk := bytes.Repeat([]byte("y"), 256) // 256 B per chunk
	chunksPerResponse := 10
	total := int64(len(chunk) * chunksPerResponse)

	b.SetBytes(total)
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp := httptest.NewRecorder()
		g := newGrpcWebResponse(resp, contentType, header.Gzip)
		for j := 0; j < chunksPerResponse; j++ {
			_, _ = g.Write(chunk)
		}
		g.finishRequest()
	}
}

func BenchmarkGrpcWebResponseStreaming_Proto_Gzip(b *testing.B) {
	benchmarkGrpcWebResponseStreaming(b, header.ApplicationGRPCWebProto)
}

func BenchmarkGrpcWebResponseStreaming_Text_Gzip(b *testing.B) {
	benchmarkGrpcWebResponseStreaming(b, header.ApplicationGRPCWebText)
}
