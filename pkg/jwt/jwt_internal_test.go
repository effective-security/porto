package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurrentKeyLastWithoutID(t *testing.T) {
	p := New(&Config{
		Issuer: "issuer.com",
		Keys: []*Key{
			{ID: "1", Seed: "seed1"},
			{ID: "2", Seed: "seed2"},
		},
	})
	id, _ := p.(*provider).currentKey()
	assert.Equal(t, "2", id)
}
