package marshal

import (
	"bufio"
	"io"
	"net/http"
	"reflect"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/limits"
	"github.com/ugorji/go/codec"
)

var (
	// jsonEncHandler is used to encode json, its configured for the most optimal output/encoding overhead
	// fields are serialized in a default order, which for maps is the map iteration order, i.e. its different
	// every time.
	jsonEncHandle codec.JsonHandle
	// jsonEncPPHandle is used to encode json with a human readable pretty printed out put, as well as
	// line breaks/indents, fields are serialized in a canonical order everytime
	jsonEncPPHandle codec.JsonHandle

	// jsonDecHandle is used to decode json
	jsonDecHandle codec.JsonHandle
)

// PrettyPrintSetting controls how to format json when encoding a go type -> json
type PrettyPrintSetting int

const (
	// DontPrettyPrint the output has no additional space/line breaks, and has random ordering of map keys
	DontPrettyPrint PrettyPrintSetting = 0

	// PrettyPrint provides an output more suitable for human consumption, it has line breaks/indenting
	// and map keys are generated in order.
	PrettyPrint PrettyPrintSetting = 1
)

func init() {

	jsonDecHandle.ErrorIfNoField = true
	jsonDecHandle.MapType = reflect.TypeOf(map[string]any{})

	jsonEncPPHandle.Canonical = true
	jsonEncPPHandle.Indent = -1
}

// shouldPrettyPrint returns true if the request indicated it would like a
// pretty printed response (by having ?pp on the URL)
func shouldPrettyPrint(r *http.Request) PrettyPrintSetting {
	_, pp := r.URL.Query()["pp"]
	if pp {
		return PrettyPrint
	}
	return DontPrettyPrint
}

// encoderHandle returns a codec handle pre-configured for the format style options
// indicated. The returned handle is shared, it should not be mutated by callers.
func encoderHandle(printSetting PrettyPrintSetting) *codec.JsonHandle {
	if printSetting == PrettyPrint {
		return &jsonEncPPHandle
	}
	return &jsonEncHandle
}

// DecoderHandle returns the codec handle used for decoding JSON into Go
// types. It errors when a JSON field has no matching Go field, and decodes
// untyped objects into map[string]any. The returned handle is shared and
// must not be mutated by callers.
func DecoderHandle() *codec.JsonHandle {
	return &jsonDecHandle
}

// NewEncoder returns a JSON encoder writing to w, pretty-printing when the
// request URL has a "pp" query parameter. r must not be nil.
func NewEncoder(w io.Writer, r *http.Request) *codec.Encoder {
	return codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r)))
}

// EncodeBytes encodes value to JSON with the given pretty-print setting and
// returns the bytes.
func EncodeBytes(printSetting PrettyPrintSetting, value any) ([]byte, error) {
	var b []byte
	err := codec.NewEncoderBytes(&b, encoderHandle(printSetting)).Encode(value)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode")
	}
	return b, err
}

// DecodeBytes decodes JSON data into result using DecoderHandle (strict:
// unknown fields are an error).
func DecodeBytes(data []byte, result any) error {
	err := codec.NewDecoderBytes(data, DecoderHandle()).Decode(result)
	if err != nil {
		return errors.Wrap(err, "failed to decode")
	}
	return nil
}

// Decode reads JSON from r and decodes it into result using DecoderHandle.
// The reader is not size-limited; wrap request bodies with
// http.MaxBytesReader first.
func Decode(r io.Reader, result any) error {
	// codec can make many little reads from the reader, so wrap it in a buffered reader
	// to keep perf lively
	err := codec.NewDecoder(bufio.NewReader(r), DecoderHandle()).Decode(result)
	if err != nil {
		return errors.Wrap(err, "unable to decode")
	}
	return nil
}

// DecodeBody decodes the JSON request body into result. On failure it
// writes a 400 invalid_json response, or 413 request_too_large on overflow,
// and returns the error, so callers can simply return. The default limit is
// limits.DefaultMaxRequestBody; LimitRequestBody overrides it. After a successful
// decode, the remaining body is consumed within the limit so trailing bytes
// cannot bypass the size check; with the limit disabled it is left unread.
// Decode and DecodeBytes remain unbounded.
func DecodeBody(w http.ResponseWriter, r *http.Request, result any) error {
	maxBytes, limited := r.Context().Value(bodyLimitKey{}).(int64)
	if !limited {
		maxBytes = limits.DefaultMaxRequestBody
		if err := limitRequestBody(w, r, maxBytes); err != nil {
			WriteJSON(w, r, err)
			return err
		}
	}
	err := Decode(r.Body, result)
	// Draining only enforces the limit; with the limit disabled it would just
	// block on a body the client keeps open.
	if err == nil && maxBytes >= 0 {
		_, err = io.Copy(io.Discard, r.Body)
		err = errors.WithMessage(err, "unable to read request body")
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			err = requestTooLarge(err)
			WriteJSON(w, r, err)
			return err
		}
		WriteJSON(
			w, r,
			httperror.New(
				http.StatusBadRequest,
				httperror.CodeInvalidJSON,
				"failed to decode '%T': %v",
				result, err.Error(),
			).WithCause(err))
		return err
	}
	return nil
}
