package gserver

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"

	"github.com/effective-security/porto/xhttp/header"
	"golang.org/x/net/http2"
)

// grpcWebResponse implements http.ResponseWriter.
type grpcWebResponse struct {
	wroteHeaders bool
	wroteBody    bool
	headers      http.Header
	// Flush must be called on this writer before returning to ensure encoded buffer is flushed
	wrapped http.ResponseWriter

	// contentType is the content type of the response.
	// It can be either "application/grpc-web+proto" or "application/grpc-web-text".
	contentType string
}

func newGrpcWebResponse(resp http.ResponseWriter, ct string) *grpcWebResponse {
	g := &grpcWebResponse{
		headers:     make(http.Header),
		wrapped:     resp,
		contentType: ct,
	}
	return g
}

func (w *grpcWebResponse) Header() http.Header {
	return w.headers
}

func (w *grpcWebResponse) Write(b []byte) (int, error) {
	if !w.wroteHeaders {
		w.prepareHeaders()
	}
	w.wroteBody, w.wroteHeaders = true, true
	if w.contentType == header.ApplicationGRPCWebText {
		// For grpc-web-text, we need to base64-encode the payload.
		encoder := base64.NewEncoder(base64.StdEncoding, w.wrapped)
		defer encoder.Close()
		return encoder.Write(b)
	}
	return w.wrapped.Write(b)
}

func (w *grpcWebResponse) WriteHeader(code int) {
	w.prepareHeaders()
	w.wrapped.WriteHeader(code)
	w.wroteHeaders = true
}

func (w *grpcWebResponse) Flush() {
	if w.wroteHeaders || w.wroteBody {
		// Work around the fact that WriteHeader and a call to Flush would have caused a 200 response.
		// This is the case when there is no payload.
		flushWriter(w.wrapped)
	}
}

// prepareHeaders runs all required header copying and transformations to
// prepare the header of the wrapped response writer.
func (w *grpcWebResponse) prepareHeaders() {
	wh := w.wrapped.Header()
	copyHeader(
		wh, w.headers,
		skipKeys("trailer"),
		replaceInKeys(http2.TrailerPrefix, ""),
		replaceInVals("content-type", header.ApplicationGRPC, w.contentType),
		keyCase(http.CanonicalHeaderKey),
	)
	responseHeaderKeys := headerKeys(wh)
	responseHeaderKeys = append(responseHeaderKeys, "grpc-status", "grpc-message")
	wh.Set(
		"access-control-expose-headers",
		strings.Join(responseHeaderKeys, ", "),
	)
}

func (w *grpcWebResponse) finishRequest() {
	if w.wroteHeaders || w.wroteBody {
		w.copyTrailersToPayload()
	} else {
		w.WriteHeader(http.StatusOK)
		flushWriter(w.wrapped)
	}
}

func (w *grpcWebResponse) copyTrailersToPayload() {
	trailers := extractTrailingHeaders(w.headers, w.wrapped.Header())
	trailerBuffer := new(bytes.Buffer)
	trailers.Write(trailerBuffer)
	trailerGrpcDataHeader := []byte{1 << 7, 0, 0, 0, 0} // MSB=1 indicates this is a trailer data frame.
	binary.BigEndian.PutUint32(trailerGrpcDataHeader[1:5], uint32(trailerBuffer.Len()))
	if w.contentType == header.ApplicationGRPCWebText {
		encoder := base64.NewEncoder(base64.StdEncoding, w.wrapped)
		defer encoder.Close()
		encoder.Write(trailerGrpcDataHeader)
		encoder.Write(trailerBuffer.Bytes())
	} else {
		w.wrapped.Write(trailerGrpcDataHeader)
		w.wrapped.Write(trailerBuffer.Bytes())
	}
	flushWriter(w.wrapped)
}

func extractTrailingHeaders(src http.Header, flushed http.Header) http.Header {
	th := make(http.Header)
	copyHeader(
		th, src,
		skipKeys(append([]string{"trailer"}, headerKeys(flushed)...)...),
		replaceInKeys(http2.TrailerPrefix, ""),
		// gRPC-Web spec says that must use lower-case header/trailer names. See
		// "HTTP wire protocols" section in
		// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md#protocol-differences-vs-grpc-over-http2
		keyCase(strings.ToLower),
	)
	return th
}

func flushWriter(w http.ResponseWriter) {
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}

	f.Flush()
}
