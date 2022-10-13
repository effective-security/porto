package pberror_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/pberror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCError(t *testing.T) {
	e1 := status.New(codes.PermissionDenied, "permission denied").Err()
	e2 := pberror.ErrGRPCPermissionDenied
	e3 := pberror.ErrPermissionDenied

	require.Equal(t, e1.Error(), e2.Error())
	assert.NotEqual(t, e1.Error(), e3.Error())

	ev1, ok := status.FromError(e1)
	assert.True(t, ok)
	assert.Equal(t, ev1.Code(), e3.(pberror.GRPCError).Code())

	ev2, ok := status.FromError(e2)
	assert.True(t, ok)
	assert.Equal(t, ev2.Code(), e3.(pberror.GRPCError).Code())

	assert.Nil(t, pberror.Error(nil))

	someErr := errors.New("some error")
	assert.NotNil(t, pberror.Error(someErr))
	assert.Equal(t, "some error", pberror.ErrorDesc(someErr))

	assert.NotNil(t, pberror.Error(e3))
	assert.Equal(t, "permission denied", pberror.ErrorDesc(e3))

	ne := pberror.New(codes.Unavailable, "some error")
	assert.Equal(t, "some error", pberror.ErrorDesc(ne))

	ev4, ok := status.FromError(ne)
	assert.True(t, ok)
	assert.Equal(t, codes.Unavailable, ev4.Code())

	ctx := correlation.WithID(context.Background())
	cid := correlation.ID(ctx)
	ne2 := pberror.NewFromCtx(ctx, codes.Unavailable, "some error")
	exp := fmt.Sprintf("request %s: some error", cid)
	assert.Equal(t, exp, pberror.ErrorDesc(ne2))
	assert.Equal(t, exp, ne2.Error())
	assert.Equal(t, cid, ne2.(pberror.GRPCError).RequestID())
}
