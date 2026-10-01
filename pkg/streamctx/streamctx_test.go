package streamctx_test

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/streamctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type ctxKey struct{}

// recordingStream is a grpc.ServerStream that records the calls it
// receives and returns err from every method that returns an error.
type recordingStream struct {
	grpc.ServerStream

	ctx     context.Context
	err     error
	header  []metadata.MD
	sent    []metadata.MD
	trailer []metadata.MD
	sentMsg []any
	recvMsg []any
}

func (s *recordingStream) Context() context.Context { return s.ctx }

func (s *recordingStream) SetHeader(md metadata.MD) error {
	s.header = append(s.header, md)
	return s.err
}

func (s *recordingStream) SendHeader(md metadata.MD) error {
	s.sent = append(s.sent, md)
	return s.err
}

func (s *recordingStream) SetTrailer(md metadata.MD) {
	s.trailer = append(s.trailer, md)
}

func (s *recordingStream) SendMsg(m any) error {
	s.sentMsg = append(s.sentMsg, m)
	return s.err
}

func (s *recordingStream) RecvMsg(m any) error {
	s.recvMsg = append(s.recvMsg, m)
	return s.err
}

func TestWithContext(t *testing.T) {
	t.Parallel()

	orig := &recordingStream{ctx: context.Background()}
	ctx1 := context.WithValue(context.Background(), ctxKey{}, "one")
	ctx2 := context.WithValue(context.Background(), ctxKey{}, "two")

	wrapped := streamctx.WithContext(ctx1, orig)
	// compare as grpc.ServerStream: a stream not produced by WithContext is
	// wrapped, not changed
	require.NotEqual(t, grpc.ServerStream(orig), wrapped)
	assert.Equal(t, "one", wrapped.Context().Value(ctxKey{}))
	// the wrapped stream keeps its own context
	assert.Nil(t, orig.Context().Value(ctxKey{}))

	// a stream produced by WithContext is updated in place
	again := streamctx.WithContext(ctx2, wrapped)
	assert.Same(t, wrapped, again)
	assert.Equal(t, "two", wrapped.Context().Value(ctxKey{}))
	assert.Nil(t, orig.Context().Value(ctxKey{}))
}

func TestWithContextDelegates(t *testing.T) {
	t.Parallel()

	errStream := errors.New("stream failed")
	tcases := []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "error", err: errStream},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			orig := &recordingStream{ctx: context.Background(), err: tc.err}
			ss := streamctx.WithContext(context.Background(), orig)

			header := metadata.Pairs("h", "1")
			sent := metadata.Pairs("s", "2")
			trailer := metadata.Pairs("t", "3")
			out := "out"
			in := new(string)

			check := func(err error) {
				if tc.err == nil {
					assert.NoError(t, err)
				} else {
					assert.ErrorIs(t, err, tc.err)
				}
			}
			check(ss.SetHeader(header))
			check(ss.SendHeader(sent))
			ss.SetTrailer(trailer)
			check(ss.SendMsg(out))
			check(ss.RecvMsg(in))

			assert.Equal(t, []metadata.MD{header}, orig.header)
			assert.Equal(t, []metadata.MD{sent}, orig.sent)
			assert.Equal(t, []metadata.MD{trailer}, orig.trailer)
			assert.Equal(t, []any{out}, orig.sentMsg)
			require.Len(t, orig.recvMsg, 1)
			assert.Same(t, in, orig.recvMsg[0])
		})
	}
}
