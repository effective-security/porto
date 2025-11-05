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
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xlog"
	"github.com/ugorji/go/codec"
	"google.golang.org/grpc/status"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto", "xhttp")

// WriteHTTPResponse is for types to implement this interface to get full control
// over how they are written out as a http response
type WriteHTTPResponse interface {
	WriteHTTPResponse(w http.ResponseWriter, r *http.Request)
}

// WriteJSON will serialize the supplied body parameter as a http response.
// If the body value implements the WriteHTTPResponse interface,
// then that will be called to have it do the response generation
// if body implements error, then that's returned as a server error
// use the Error type to fully specify your error response
// otherwise body is assumed to be a succesful response, and its serialized
// and written as a json response with a 200 status code.
//
// multiple body parameters can be supplied, in which case the first
// non-nil one will be used. This is useful as it allows you to do
//
//		x, err := doSomething()
//		WriteJSON(logger,w,r,err,x)
//	and if there was an error, that's what'll get returned
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
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		var out io.Writer = w
		if r != nil && strings.Contains(r.Header.Get(header.AcceptEncoding), header.Gzip) {
			w.Header().Set(header.ContentEncoding, header.Gzip)
			gz := gzip.NewWriter(out)
			out = gz
			defer gz.Close()
		}
		bw := bufio.NewWriter(out)
		if err := NewEncoder(bw, r).Encode(body); err != nil {

			logger.ContextKV(r.Context(), xlog.WARNING, "reason", "encode", "type", body, "err", err.Error())

		}
		bw.Flush()
	}
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
			logger.ContextKV(ctx, sv, "err", cause)
		} else {
			logger.ContextKV(ctx, sv, "err", cause.Error())
		}
	}

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

// WritePlainJSON will serialize the supplied body parameter as a http response.
func WritePlainJSON(w http.ResponseWriter, statusCode int, body any, printSetting PrettyPrintSetting) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(statusCode)

	_ = codec.NewEncoder(w, encoderHandle(printSetting)).Encode(body)

}

// NewRequest returns http.Request
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
