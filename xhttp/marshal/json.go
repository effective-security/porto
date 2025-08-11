// Package marshal provides some common handlers for encoding or decoding json
package marshal

import (
	"bufio"
	"io"
	"net/http"
	"reflect"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/pkg/errors"
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
	jsonDecHandle.MapType = reflect.TypeOf(map[string]interface{}{})

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

// DecoderHandle returns a code handle pre-configured for decoding json back into go
// types. It is setup to error when a field in the json has no matching field in the
// go type, and that all maps are deserialized into a map[stirng]interface{}
// the returned handle is shared, it should not be mutated by callers.
func DecoderHandle() *codec.JsonHandle {
	return &jsonDecHandle
}

// NewEncoder returns a new Encoder ready to write a value, its configured
// based on the request [currently just if it should pretty print or not]
func NewEncoder(w io.Writer, r *http.Request) *codec.Encoder {
	return codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r)))
}

// EncodeBytes is a helper that takes the supplied go value, and encoded it to json
// and returned the byte slice containing the encoded value.
func EncodeBytes(printSetting PrettyPrintSetting, value interface{}) ([]byte, error) {
	var b []byte
	err := codec.NewEncoderBytes(&b, encoderHandle(printSetting)).Encode(value)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode")
	}
	return b, err
}

// DecodeBytes is a helper that takes the supplied json and decodes it into
// the supplied result instance.
func DecodeBytes(data []byte, result interface{}) error {
	err := codec.NewDecoderBytes(data, DecoderHandle()).Decode(result)
	if err != nil {
		return errors.Wrap(err, "failed to decode")
	}
	return nil
}

// Decode will read the json from the supplied reader,
// and decode it into the supplied result instance.
func Decode(r io.Reader, result interface{}) error {
	// codec can make many little reads from the reader, so wrap it in a buffered reader
	// to keep perf lively
	err := codec.NewDecoder(bufio.NewReader(r), DecoderHandle()).Decode(result)
	if err != nil {
		return errors.Wrap(err, "unable to decode")
	}
	return nil
}

// DecodeBody will read the json from the HTTP request body,
// and decode it into the supplied result instance.
// If error occured, then it will write to the response
func DecodeBody(w http.ResponseWriter, r *http.Request, result interface{}) error {
	err := Decode(r.Body, result)
	if err != nil {
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
