package testutils_test

import (
	"testing"

	"github.com/effective-security/porto/tests/testutils"
	"github.com/stretchr/testify/assert"
)

func TestCreateBindAddrInvalidHost(t *testing.T) {
	t.Parallel()
	// An embedded port makes the host invalid without requiring DNS or a
	// machine-dependent port conflict. The helper promises to panic on failure.
	assert.Panics(t, func() { testutils.CreateBindAddr("127.0.0.1:1") })
}
