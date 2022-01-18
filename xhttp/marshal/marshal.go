package marshal

import (
	"bufio"
	"compress/gzip"
	goErrors "errors"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xlog"
	"github.com/ugorji/go/codec"
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
//		x, err := doSomething()
//		WriteJSON(logger,w,r,err,x)
//	and if there was an error, that's what'll get returned
//
func WriteJSON(w http.ResponseWriter, r *http.Request, bodies ...interface{}) {
	var body interface{}
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
		logger.Debugf("reason=generic_error, type='%T', err=[%v]", bv, bv)
		WriteJSON(w, r, httperror.Unexpected(bv.Error()))
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
			logger.Warningf("reason=encode, type=%T, err=[%v]", body, err.Error())
		}
		bw.Flush()
	}
}

func httpError(bv interface{}, r *http.Request) {
	// notice that we're using 2, so it will actually log where
	// the error happened, 0 = this function, we don't want that.
	_, fn, line, _ := runtime.Caller(2)

	if e, ok := bv.(*httperror.Error); ok {
		sv := xlog.WARNING
		typ := "API_ERROR"
		if e.HTTPStatus >= 500 {
			sv = xlog.ERROR
			typ = "INTERNAL_ERROR"
		}
		logger.KV(sv,
			"type", typ,
			"path", r.URL.Path,
			"status", e.HTTPStatus,
			"code", e.Code,
			"msg", e.Message,
			"fn", fn,
			"ln", line,
			"err", e.Cause,
		)
	}
}

// WritePlainJSON will serialize the supplied body parameter as a http response.
func WritePlainJSON(w http.ResponseWriter, statusCode int, body interface{}, printSetting PrettyPrintSetting) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(statusCode)
	if err := codec.NewEncoder(w, encoderHandle(printSetting)).Encode(body); err != nil {
		logger.Warningf("reason=encode, type=%T, err=[%v]", body, err.Error())
	}
}
