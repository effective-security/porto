package httperror

import (
	"net/http"

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
)

func init() {
	jsonEncPPHandle.BasicHandle.EncodeOptions.Canonical = true
	jsonEncPPHandle.Indent = -1
}

// shouldPrettyPrint returns true if the request indicated it would like a
// pretty printed response (by having ?pp on the URL)
func shouldPrettyPrint(r *http.Request) bool {
	_, pp := r.URL.Query()["pp"]
	return pp
}

// encoderHandle returns a codec handle pre-configured for the format style options
// indicated. The returned handle is shared, it should not be mutated by callers.
func encoderHandle(pretty bool) *codec.JsonHandle {
	if pretty {
		return &jsonEncPPHandle
	}
	return &jsonEncHandle
}
