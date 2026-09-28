package gserver

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
)

var grpcWebGzipWriters = sync.Pool{
	New: func() any { return gzip.NewWriter(io.Discard) },
}

// errWriteAfterClose is returned for body writes to a compressed response
// after Close: the gzip footer is already written, so appending bytes would
// corrupt the body.
var errWriteAfterClose = errors.New("gRPC-Web response: write after close")

// grpcWebResponse implements http.ResponseWriter.
type grpcWebResponse struct {
	wroteHeaders bool
	wroteBody    bool
	headers      http.Header
	// Flush must be called on this writer before returning to ensure encoded buffer is flushed
	wrapped http.ResponseWriter

	compress bool
	// exposeHeaders enables the gRPC-Web CORS exposure list for an allowed origin.
	exposeHeaders bool
	// gz is the pooled gzip writer of a compressed response; Close returns
	// it to the pool and sets it to nil.
	gz *gzip.Writer

	// contentType is the content type of the response.
	// It can be either "application/grpc-web+proto" or "application/grpc-web-text".
	contentType string
}

// newGrpcWebResponse creates a grpcWebResponse.
//
// When compress is true, the response body is transparently gzip-compressed and
// the appropriate Content-Encoding header is set. Compression MUST only be
// enabled for unary (non-streaming) responses: gRPC-Web has no concept of
// HTTP-level streaming compression, and gzip-ing a stream forces the whole body
// to be buffered (emitting a fixed Content-Length) and swallows per-message
// flushes, which breaks streaming. The caller is responsible for disabling
// compression for streaming calls (see header.XGRPCStream).
func newGrpcWebResponse(resp http.ResponseWriter, ct string, compress bool) *grpcWebResponse {
	g := &grpcWebResponse{
		headers:     make(http.Header),
		wrapped:     resp,
		contentType: ct,
	}

	if compress {
		g.compress = true
		g.gz = grpcWebGzipWriters.Get().(*gzip.Writer)
		g.gz.Reset(resp)
		// The Content-Encoding header must be set before headers are written.
		resp.Header().Set(header.ContentEncoding, header.Gzip)
	}
	return g
}

func (w *grpcWebResponse) Header() http.Header {
	return w.headers
}

func (w *grpcWebResponse) Write(b []byte) (int, error) {
	dest, err := w.sink()
	if err != nil {
		return 0, err
	}

	// Ensure headers have been sent once.
	if !w.wroteHeaders {
		w.prepareHeaders()
	}
	w.wroteBody, w.wroteHeaders = true, true

	// grpc-web-text requires base64 encoding of the message body.
	if w.contentType == header.ApplicationGRPCWebText {
		return w.writeTextPayload(dest, b)
	}

	// Binary gRPC-Web – write directly.
	return dest.Write(b)
}

// sink returns the destination for body bytes: the gzip writer for a
// compressed response, otherwise the wrapped http.ResponseWriter. A
// compressed response that has been closed returns errWriteAfterClose
// instead of falling back to the uncompressed writer.
func (w *grpcWebResponse) sink() (io.Writer, error) {
	if !w.compress {
		return w.wrapped, nil
	}
	if w.gz == nil {
		return nil, errors.WithStack(errWriteAfterClose)
	}
	return w.gz, nil
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
		err := enc.Close()
		if err != nil {
			return 0, err
		}
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
	if w.wroteHeaders || w.wroteBody {
		// Work around the fact that WriteHeader and a call to Flush would have caused a 200 response.
		// This is the case when there is no payload.
		if w.compress && w.gz != nil {
			// Unary, compressed response: flush the gzip writer only. We do NOT
			// flush the wrapped writer here so net/http can still compute a
			// Content-Length for the buffered body.
			err := w.gz.Flush()
			if err != nil {
				logger.KV(xlog.ERROR,
					"reason", "failed_to_flush_gzip",
					"err", err.Error())
			}
		} else {
			// Streaming (uncompressed) response: forwarding to the underlying
			// writer is what enables streaming – each per-message flush is sent
			// to the client as a chunk/DATA frame.
			flushWriter(w.wrapped)
		}
	}
}

func (w *grpcWebResponse) Close() {
	if w.compress && w.gz != nil {
		gz := w.gz
		w.gz = nil
		err := gz.Close()
		gz.Reset(io.Discard)
		grpcWebGzipWriters.Put(gz)
		if err != nil {
			logger.KV(xlog.ERROR,
				"reason", "failed_to_close_gzip",
				"err", err.Error())
		}
	}
}

// prepareHeaders runs all required header copying and transformations to
// prepare the header of the wrapped response writer.
func (w *grpcWebResponse) prepareHeaders() {
	wh := w.wrapped.Header()
	configuredExposed := wh.Values("Access-Control-Expose-Headers")
	responseExposed := w.headers.Values("Access-Control-Expose-Headers")
	copyHeader(
		wh, w.headers,
		skipKeys(
			"trailer",
			"access-control-allow-origin",
			"access-control-allow-credentials",
			"access-control-expose-headers",
			header.Vary,
			http.TrailerPrefix+"Access-Control-Allow-Origin",
			http.TrailerPrefix+"Access-Control-Allow-Credentials",
			http.TrailerPrefix+"Access-Control-Expose-Headers",
			http.TrailerPrefix+header.Vary,
		),
		replaceInKeys(http.TrailerPrefix, ""),
		replaceInVals("content-type", header.ApplicationGRPC, w.contentType),
		keyCase(http.CanonicalHeaderKey),
	)
	mergeVaryHeader(wh, w.headers)
	if w.exposeHeaders {
		exposed := make([]string, 0, len(wh)+2)
		seen := make(map[string]bool, len(wh)+2)
		add := func(name string) {
			name = strings.TrimSpace(name)
			key := strings.ToLower(name)
			if name != "" && !seen[key] {
				seen[key] = true
				exposed = append(exposed, name)
			}
		}
		for _, values := range [][]string{configuredExposed, responseExposed} {
			for _, value := range values {
				for name := range strings.SplitSeq(value, ",") {
					add(name)
				}
			}
		}
		for _, name := range headerKeys(wh) {
			add(name)
		}
		add("grpc-status")
		add("grpc-message")
		wh.Set("Access-Control-Expose-Headers", strings.Join(exposed, ", "))
	}
}

// mergeVaryHeader keeps server-selected cache keys when gRPC metadata also
// includes Vary. A wildcard means every request field may affect the response.
func mergeVaryHeader(dst, src http.Header) {
	var metadataVary []string
	for key, values := range src {
		if strings.EqualFold(key, header.Vary) || strings.EqualFold(key, http.TrailerPrefix+header.Vary) {
			metadataVary = append(metadataVary, values...)
		}
	}
	if len(metadataVary) == 0 {
		return
	}

	var merged []string
	seen := make(map[string]bool)
	for _, values := range [][]string{dst.Values(header.Vary), metadataVary} {
		for _, value := range values {
			for field := range strings.SplitSeq(value, ",") {
				field = strings.TrimSpace(field)
				if field == "*" {
					dst.Set(header.Vary, "*")
					return
				}
				key := strings.ToLower(field)
				if field != "" && !seen[key] {
					seen[key] = true
					merged = append(merged, field)
				}
			}
		}
	}
	if len(merged) > 0 {
		dst.Set(header.Vary, strings.Join(merged, ", "))
	}
}

func (w *grpcWebResponse) finishRequest() {
	if w.wroteHeaders || w.wroteBody {
		w.copyTrailersToPayload()
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Finalize gzip writer (if any) to flush remaining bytes and write the footer.
	if w.compress && w.gz != nil {
		w.Close()
	} else {
		flushWriter(w.wrapped)
	}
}

func (w *grpcWebResponse) copyTrailersToPayload() {
	// Decide where the bytes go: gzip writer (if enabled) or the original response writer.
	dest, err := w.sink()
	if err != nil {
		logger.KV(xlog.ERROR,
			"reason", "failed_to_write_frame",
			"err", err.Error())
		return
	}

	// Build the binary gRPC-Web trailer frame once.
	frame := buildTrailerFrame(extractTrailingHeaders(w.headers, w.wrapped.Header()))

	// For text mode we must base64-encode the frame before sending it (and *then* optionally gzip it).
	if w.contentType == header.ApplicationGRPCWebText {
		enc := base64.NewEncoder(base64.StdEncoding, dest)
		_, err = enc.Write(frame)
		if err != nil {
			logger.KV(xlog.ERROR,
				"reason", "failed_to_write_base64_frame",
				"err", err.Error())
		}
		err = enc.Close()
		if err != nil {
			logger.KV(xlog.ERROR,
				"reason", "failed_to_close_base64_encoder",
				"err", err.Error())
		}
		return
	}

	// Binary mode – write frame directly.
	_, err = dest.Write(frame)
	if err != nil {
		logger.KV(xlog.ERROR,
			"reason", "failed_to_write_frame",
			"err", err.Error())
	}
}

// buildTrailerFrame turns HTTP trailers into a single gRPC-Web data frame as per the spec.
// The returned slice layout is: [flags(1)][length(4)][payload].
func buildTrailerFrame(trailers http.Header) []byte {
	var payload bytes.Buffer
	err := trailers.Write(&payload)
	if err != nil {
		logger.KV(xlog.ERROR,
			"reason", "failed_to_write_trailers",
			"err", err.Error())
	}

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
		replaceInKeys(http.TrailerPrefix, ""),
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
