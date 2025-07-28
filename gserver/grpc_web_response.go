package gserver

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"io"
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

	compress bool
	gz       *gzip.Writer

	// contentType is the content type of the response.
	// It can be either "application/grpc-web+proto" or "application/grpc-web-text".
	contentType string
}

// newGrpcWebResponse creates a grpcWebResponse. If the client indicated that it
// accepts gzip encoding ("Accept-Encoding" contains "gzip"), the response will
// be transparently compressed and the appropriate headers will be set.
func newGrpcWebResponse(resp http.ResponseWriter, ct string, acceptEncoding string) *grpcWebResponse {
	g := &grpcWebResponse{
		headers:     make(http.Header),
		wrapped:     resp,
		contentType: ct,
	}

	// Enable gzip compression only if requested by the client and only once
	// per response.
	if strings.Contains(acceptEncoding, header.Gzip) {
		g.compress = true
		g.gz = gzip.NewWriter(resp)
		// The Content-Encoding header must be set before headers are written.
		resp.Header().Set(header.ContentEncoding, header.Gzip)
	}
	return g
}

func (w *grpcWebResponse) Header() http.Header {
	return w.headers
}

func (w *grpcWebResponse) Write(b []byte) (int, error) {
	// Ensure headers have been sent once.
	if !w.wroteHeaders {
		w.prepareHeaders()
	}
	w.wroteBody, w.wroteHeaders = true, true

	// Select the final sink – either a gzip writer or the raw http.ResponseWriter.
	dest := io.Writer(w.wrapped)
	if w.compress && w.gz != nil {
		dest = w.gz
	}

	// grpc-web-text requires base64 encoding of the message body.
	if w.contentType == header.ApplicationGRPCWebText {
		return w.writeTextPayload(dest, b)
	}

	// Binary gRPC-Web – write directly.
	return dest.Write(b)
}

// writeTextPayload writes a grpc-web-text message body (base64). If gzip is
// active we must encode first, then compress – hence the buffer.
func (w *grpcWebResponse) writeTextPayload(dest io.Writer, b []byte) (int, error) {
	// When gzip is enabled we cannot stream base64 directly to the gzip writer
	// because we need to close the encoder to flush final padding bytes. Doing
	// so after gzip.Close would corrupt the stream. Therefore, encode to a
	// buffer first, then pass it to gzip.
	if w.compress && w.gz != nil {
		var buf bytes.Buffer
		enc := base64.NewEncoder(base64.StdEncoding, &buf)
		if _, err := enc.Write(b); err != nil {
			return 0, err
		}
		_ = enc.Close()
		return dest.Write(buf.Bytes())
	}

	enc := base64.NewEncoder(base64.StdEncoding, dest)
	defer enc.Close()
	return enc.Write(b)
}

func (w *grpcWebResponse) WriteHeader(code int) {
	w.prepareHeaders()
	w.wrapped.WriteHeader(code)
	w.wroteHeaders = true
}

func (w *grpcWebResponse) Flush() {
	if w.compress && w.gz != nil {
		_ = w.gz.Flush()
	}
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
	}

	// Finalize gzip writer (if any) to flush remaining bytes and write the footer.
	if w.compress && w.gz != nil {
		_ = w.gz.Close()
	}

	// Ensure the underlying writer is flushed to the client.
	flushWriter(w.wrapped)
}

func (w *grpcWebResponse) copyTrailersToPayload() {
	// Build the binary gRPC-Web trailer frame once.
	frame := buildTrailerFrame(extractTrailingHeaders(w.headers, w.wrapped.Header()))

	// Decide where the bytes go: gzip writer (if enabled) or the original response writer.
	dest := io.Writer(w.wrapped)
	if w.compress && w.gz != nil {
		dest = w.gz
	}

	// For text mode we must base64-encode the frame before sending it (and *then* optionally gzip it).
	if w.contentType == header.ApplicationGRPCWebText {
		enc := base64.NewEncoder(base64.StdEncoding, dest)
		_, _ = enc.Write(frame)
		_ = enc.Close()
		return
	}

	// Binary mode – write frame directly.
	_, _ = dest.Write(frame)
}

// buildTrailerFrame turns HTTP trailers into a single gRPC-Web data frame as per the spec.
// The returned slice layout is: [flags(1)][length(4)][payload].
func buildTrailerFrame(trailers http.Header) []byte {
	var payload bytes.Buffer
	_ = trailers.Write(&payload)

	// As per gRPC-Web, set MSB of the first byte to 1 to mark a trailer frame.
	frame := make([]byte, 5+payload.Len())
	frame[0] = 1 << 7
	binary.BigEndian.PutUint32(frame[1:5], uint32(payload.Len()))
	copy(frame[5:], payload.Bytes())
	return frame
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
