package pberror_test

import (
	"context"
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
	e3 := pberror.ErrGRPCTimeout

	require.Equal(t, e1.Error(), e2.Error())
	assert.NotEqual(t, e1.Error(), e3.Error())

	ev1, ok := status.FromError(e1)
	assert.True(t, ok)
	assert.Equal(t, ev1.Code(), pberror.Code(e2))
	assert.NotEqual(t, ev1.Code(), pberror.Code(e3))

	ev2, ok := status.FromError(e2)
	assert.True(t, ok)
	assert.Equal(t, ev2.Code(), pberror.Code(e1))

	ne := pberror.New(codes.Unavailable, "some error")
	assert.Equal(t, "some error", pberror.Message(ne))

	ev4, ok := status.FromError(ne)
	assert.True(t, ok)
	assert.Equal(t, codes.Unavailable, ev4.Code())

	ctx := correlation.WithID(context.Background())
	cid := correlation.ID(ctx)
	assert.NotEmpty(t, cid)
	ne2 := pberror.NewFromCtx(ctx, codes.Unavailable, "some error")
	assert.Equal(t, "some error", pberror.Message(ne2))
	assert.Equal(t, cid, pberror.CorrelationID(ne2))
	exp := fmt.Sprintf("request %s: some error", cid)
	assert.Equal(t, exp, pberror.Error(ne2))
}
