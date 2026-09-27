package marshal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	goErrors "errors"
	"io"
	"net/http"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xlog"
	"github.com/ugorji/go/codec"
	"google.golang.org/grpc/status"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto", "xhttp")

const minGzipSize = 1024

var jsonGzipWriters = sync.Pool{
	New: func() any { return gzip.NewWriter(io.Discard) },
}

// WriteHTTPResponse is implemented by types that take full control over how
// they are written as an HTTP response (httperror.Error and ManyError do).
type WriteHTTPResponse interface {
	// WriteHTTPResponse writes the value, including status and headers, to w.
	WriteHTTPResponse(w http.ResponseWriter, r *http.Request)
}

// WriteJSON serialises the first non-nil body value as the HTTP response.
// A value implementing WriteHTTPResponse writes itself (httperror values
// set their own status); any other error is converted with
// httperror.NewFromPb (500 unexpected unless it carries a gRPC status) and
// written the same way; errors other than 404 are also logged with the
// caller's file and line. Anything else is written as application/json
// with status 200, gzip-compressed for payloads of at least 1 KiB when the
// request accepts gzip, and pretty-printed when the URL has a "pp" query
// parameter. Success responses vary by Accept-Encoding. Encoding and write
// failures are logged, not reported. r must not be nil.
//
// Passing several values lets a handler write either the error or the
// result in one call:
//
//	x, err := doSomething()
//	marshal.WriteJSON(w, r, err, x)
func WriteJSON(w http.ResponseWriter, r *http.Request, bodies ...any) {
	var body any
	for i := range bodies {
		if bodies[i] != nil {
			body = bodies[i]
			break
		}
	}

	switch bv := body.(type) {
	case WriteHTTPResponse:
		// errors.Error impls WriteHTTPResponse, so will take this path and do its thing
		bv.WriteHTTPResponse(w, r)
		httpError(bv, r)
		return

	case error:
		var resp WriteHTTPResponse

		if goErrors.As(bv, &resp) {
			resp.WriteHTTPResponse(w, r)
			httpError(bv, r)
			return
		}

		// you should really be using Error to get a good error response returned

		// logger.ContextKV(r.Context(), xlog.WARNING, "reason", "generic_error", "type", bv, "err", bv)
		WriteJSON(w, r, httperror.NewFromPb(bv))

		return

	default:
		h := w.Header()
		h.Set(header.ContentType, header.ApplicationJSON)
		addVaryAcceptEncoding(h)
		var out io.Writer = w
		var compressed *thresholdGzipWriter
		if acceptsGzip(r.Header) {
			compressed = &thresholdGzipWriter{w: w}
			out = compressed
		}
		bw := bufio.NewWriter(out)
		encodeErr := NewEncoder(bw, r).Encode(body)
		flushErr := bw.Flush()
		var closeErr error
		if compressed != nil {
			closeErr = compressed.Close()
		}
		if encodeErr != nil {
			logger.ContextKV(r.Context(), xlog.WARNING, "reason", "encode", "type", body, "err", encodeErr.Error())
		}
		if flushErr != nil {
			logger.ContextKV(r.Context(), xlog.WARNING, "reason", "flush_json", "err", flushErr.Error())
		}
		if closeErr != nil {
			logger.ContextKV(r.Context(), xlog.WARNING, "reason", "close_json", "err", closeErr.Error())
		}
	}
}

// thresholdGzipWriter keeps at most minGzipSize-1 bytes before deciding
// whether to compress. Once the threshold is reached, it streams to gzip.
type thresholdGzipWriter struct {
	w      http.ResponseWriter
	buffer [minGzipSize]byte
	used   int
	gz     *gzip.Writer
}

func (tw *thresholdGzipWriter) Write(p []byte) (int, error) {
	if tw.gz != nil {
		return tw.gz.Write(p)
	}
	if tw.used+len(p) < minGzipSize {
		tw.used += copy(tw.buffer[tw.used:], p)
		return len(p), nil
	}
	tw.w.Header().Set(header.ContentEncoding, header.Gzip)
	tw.gz = jsonGzipWriters.Get().(*gzip.Writer)
	tw.gz.Reset(tw.w)
	if tw.used > 0 {
		if _, err := tw.gz.Write(tw.buffer[:tw.used]); err != nil {
			return 0, errors.WithMessage(err, "unable to write compressed JSON prefix")
		}
		tw.used = 0
	}
	return tw.gz.Write(p)
}

func (tw *thresholdGzipWriter) Close() error {
	if tw.gz == nil {
		if tw.used == 0 {
			return nil
		}
		_, err := tw.w.Write(tw.buffer[:tw.used])
		tw.used = 0
		if err != nil {
			return errors.WithMessage(err, "unable to write JSON")
		}
		return nil
	}
	gz := tw.gz
	tw.gz = nil
	err := gz.Close()
	gz.Reset(io.Discard)
	jsonGzipWriters.Put(gz)
	if err != nil {
		return errors.WithMessage(err, "unable to close compressed JSON")
	}
	return nil
}

func addVaryAcceptEncoding(h http.Header) {
	for _, field := range h.Values(header.Vary) {
		for value := range strings.SplitSeq(field, ",") {
			value = strings.TrimSpace(value)
			if value == "*" || strings.EqualFold(value, header.AcceptEncoding) {
				return
			}
		}
	}
	h.Add(header.Vary, header.AcceptEncoding)
}

func acceptsGzip(h http.Header) bool {
	var gzipQuality, wildcardQuality float64
	var gzipSeen, wildcardSeen bool
	for _, field := range h.Values(header.AcceptEncoding) {
		for item := range strings.SplitSeq(field, ",") {
			coding, parameters, _ := strings.Cut(strings.TrimSpace(item), ";")
			coding = strings.TrimSpace(coding)
			isGzip := strings.EqualFold(coding, header.Gzip)
			if !isGzip && coding != "*" {
				continue
			}
			// Quality defaults to 1 when no q parameter is present; a
			// malformed or out-of-range q value is treated as a refusal.
			quality := 1.0
			for parameter := range strings.SplitSeq(parameters, ";") {
				name, value, _ := strings.Cut(parameter, "=")
				if !strings.EqualFold(strings.TrimSpace(name), "q") {
					continue
				}
				quality = 0
				parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err == nil && parsed >= 0 && parsed <= 1 {
					quality = parsed
				}
				break
			}
			if isGzip {
				gzipSeen = true
				gzipQuality = max(gzipQuality, quality)
			} else {
				wildcardSeen = true
				wildcardQuality = max(wildcardQuality, quality)
			}
		}
	}
	if gzipSeen {
		return gzipQuality > 0
	}
	return wildcardSeen && wildcardQuality > 0
}

func httpError(bv any, r *http.Request) {
	if e, ok := bv.(*httperror.Error); ok {
		logError(r, e.HTTPStatus, e.Code, e.Message, e.Cause())
	} else if e, ok := bv.(*httperror.ManyError); ok {
		logError(r, e.HTTPStatus, e.Code, e.Message, e.Cause())
	} else if err, ok := bv.(error); ok {
		var he *httperror.Error
		if goErrors.As(err, &he) {
			logError(r, he.HTTPStatus, he.Code, he.Message, he.Cause())
		} else if se, ok := err.(interface {
			GRPCStatus() *status.Status
		}); ok {
			st := se.GRPCStatus()
			logError(r, int(st.Code()), "rpc", st.Message(), nil)
		} else {
			logError(r, http.StatusInternalServerError, httperror.CodeUnexpected, err.Error(), nil)
		}
	}
}

func logError(r *http.Request, status int, code, message string, cause error) {
	if status == http.StatusNotFound {
		return
	}
	// notice that we're using 2, so it will actually log where
	// the error happened, 0 = this function, we don't want that.
	_, fn, line, _ := runtime.Caller(3)

	ctx := r.Context()
	sv := xlog.INFO
	typ := "API_ERROR"
	if status >= 500 {
		sv = xlog.ERROR
		typ = "INTERNAL_ERROR"
	}

	if cause != nil {
		if sv == xlog.ERROR {
			// for ERROR log with stack
			logger.ContextKV(ctx, sv,
				"type", typ,
				"path", r.URL.Path,
				"status", status,
				"code", code,
				"msg", message,
				"agent", r.UserAgent(),
				"content-type", r.Header.Get(header.ContentType),
				"accept", r.Header.Get(header.Accept),
				"content-length", r.ContentLength,
				"fn", path.Base(fn),
				"ln", line,
				"err", cause,
			)
		} else {
			logger.ContextKV(ctx, sv,
				"type", typ,
				"path", r.URL.Path,
				"status", status,
				"code", code,
				"msg", message,
				"agent", r.UserAgent(),
				"content-type", r.Header.Get(header.ContentType),
				"accept", r.Header.Get(header.Accept),
				"content-length", r.ContentLength,
				"fn", path.Base(fn),
				"ln", line,
				"err", cause.Error())
		}
	} else {
		logger.ContextKV(ctx, sv,
			"type", typ,
			"path", r.URL.Path,
			"status", status,
			"code", code,
			"msg", message,
			"agent", r.UserAgent(),
			"content-type", r.Header.Get(header.ContentType),
			"accept", r.Header.Get(header.Accept),
			"content-length", r.ContentLength,
			"fn", path.Base(fn),
			"ln", line,
		)
	}
}

// WritePlainJSON writes body as application/json with the given status
// code and pretty-print setting, without gzip, error handling or logging.
func WritePlainJSON(w http.ResponseWriter, statusCode int, body any, printSetting PrettyPrintSetting) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(statusCode)

	_ = codec.NewEncoder(w, encoderHandle(printSetting)).Encode(body)

}

// NewRequest builds an http.Request whose body is req: an io.Reader, []byte
// or string is sent as is, anything else is JSON-encoded with encoding/json.
// No Content-Type header is set.
func NewRequest(method string, url string, req any) (*http.Request, error) {
	var body io.Reader

	switch val := req.(type) {
	case io.Reader:
		body = val
	case []byte:
		body = bytes.NewReader(val)
	case string:
		body = strings.NewReader(val)
	default:
		js, err := json.Marshal(req)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		body = bytes.NewReader(js)
	}

	return http.NewRequest(method, url, body)
}
