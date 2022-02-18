package identity

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
)

// BasicAuthFromRequest returns client id from Basic authentication,
// which is in base64encode(id:secret) form
func BasicAuthFromRequest(r *http.Request) (id string, secret string, err error) {
	authHeader := r.Header.Get(header.Authorization)
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return
	}

	tok, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		err = httperror.InvalidRequest("invalid Authorization header")
		return
	}
	idx := bytes.IndexByte(tok, byte(':'))
	if idx < 0 {
		id = string(tok)
	} else {
		id = string(tok[:idx])
		secret = string(tok[idx+1:])
	}
	return
}
