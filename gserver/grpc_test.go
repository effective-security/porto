package gserver_test

import (
	"context"
	"io"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/metrics"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/tests/mockappcontainer"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The echo service is registered from a hand-written ServiceDesc. Echo
// returns its request value unless the value selects one of the echo*
// behaviors; Watch streams the request value back watchCount times, or
// fails for echoStatus; Block waits until its stream ends.
const (
	echoServiceName = "porto.test.Echo"
	echoMethod      = "/porto.test.Echo/Echo"
	watchMethod     = "/porto.test.Echo/Watch"
	blockMethod     = "/porto.test.Echo/Block"

	echoInvalid       = "invalid"        // rejected by echoRequest.Validate
	echoValidatePanic = "validate-panic" // echoRequest.Validate panics
	echoPanic         = "panic"          // the handler panics
	echoNotFound      = "not-found"      // *httperror.Error with NotFound
	echoInternal      = "internal"       // *httperror.Error with a cause
	echoMany          = "many"           // *httperror.ManyError
	echoStatus        = "status"         // a FailedPrecondition gRPC status
	echoLarge         = "large"          // a response of largeMessageSize bytes

	watchCount       = 3
	largeMessageSize = 2048
	smallMessageSize = 512
	messageSizeLimit = 1024
	echoTimeout      = 5 * time.Second
	grpcMetricsName  = "gservergrpc"
)

// echoRequest is decoded by the proto codec through its embedded message
// and implements gserver.Validator.
type echoRequest struct {
	*wrapperspb.BytesValue
}

func (r *echoRequest) Validate(context.Context) error {
	switch string(r.GetValue()) {
	case echoInvalid:
		return status.Error(codes.InvalidArgument, "invalid echo request")
	case echoValidatePanic:
		panic("echo validation panic")
	}
	return nil
}

type echoServer struct {
	// calls counts the Echo handler invocations
	calls atomic.Int32
	// blocked receives a value when a Block stream starts
	blocked chan struct{}
}

func newEchoServer() *echoServer {
	return &echoServer{blocked: make(chan struct{}, 1)}
}

func (s *echoServer) Name() string  { return "echo" }
func (s *echoServer) IsReady() bool { return true }
func (s *echoServer) Close()        {}

func (s *echoServer) RegisterGRPC(gs *grpc.Server) {
	gs.RegisterService(&grpc.ServiceDesc{
		ServiceName: echoServiceName,
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Echo",
				Handler: func(_ any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					in := &echoRequest{BytesValue: &wrapperspb.BytesValue{}}
					if err := dec(in); err != nil {
						return nil, err
					}
					info := &grpc.UnaryServerInfo{Server: s, FullMethod: echoMethod}
					return interceptor(ctx, in, info, func(ctx context.Context, req any) (any, error) {
						return s.echo(ctx, req.(*echoRequest))
					})
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Watch",
				ServerStreams: true,
				Handler: func(_ any, stream grpc.ServerStream) error {
					in := &wrapperspb.BytesValue{}
					if err := stream.RecvMsg(in); err != nil {
						return err
					}
					if string(in.GetValue()) == echoStatus {
						return status.Error(codes.FailedPrecondition, "watch precondition failed")
					}
					for range watchCount {
						if err := stream.SendMsg(in); err != nil {
							return err
						}
					}
					return nil
				},
			},
			{
				StreamName:    "Block",
				ServerStreams: true,
				Handler: func(_ any, stream grpc.ServerStream) error {
					s.blocked <- struct{}{}
					<-stream.Context().Done()
					return stream.Context().Err()
				},
			},
		},
	}, s)
}

func (s *echoServer) echo(_ context.Context, in *echoRequest) (*wrapperspb.BytesValue, error) {
	s.calls.Add(1)
	switch string(in.GetValue()) {
	case echoPanic:
		panic("echo handler panic")
	case echoNotFound:
		return nil, httperror.NotFound("echo item not found")
	case echoInternal:
		return nil, httperror.Unexpected("echo failed").WithCause(errors.New("echo backend is down"))
	case echoMany:
		return nil, httperror.NewMany(http.StatusBadRequest, httperror.CodeInvalidRequest, "echo rejected").
			Add("value", httperror.InvalidRequest("bad value"))
	case echoStatus:
		return nil, status.Error(codes.FailedPrecondition, "echo precondition failed")
	case echoLarge:
		return wrapperspb.Bytes(make([]byte, largeMessageSize)), nil
	}
	return wrapperspb.Bytes(in.GetValue()), nil
}

// startEcho starts a server with the echo service, on a TLS listener when
// cfg.ServerTLS is set and on a plaintext one otherwise, and returns a
// client connection to it. cfg may set any field except ListenURLs and
// Services.
func startEcho(t *testing.T, cfg *gserver.Config, svc *echoServer, opts ...gserver.Option) (gserver.GServer, *grpc.ClientConn) {
	t.Helper()
	creds := insecure.NewCredentials()
	cfg.ListenURLs = []string{"http://127.0.0.1:0"}
	if cfg.ServerTLS != nil {
		cfg.ListenURLs = []string{"https://127.0.0.1:0"}
		clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", cfg.ServerTLS.TrustedCAFile)
		require.NoError(t, err)
		// the legacy test fixture has no SANs
		clientTLS.InsecureSkipVerify = true
		creds = credentials.NewTLS(clientTLS)
	}
	cfg.Services = []string{svc.Name()}
	factories := map[string]gserver.ServiceFactory{
		svc.Name(): func(server gserver.GServer) any {
			return func() {
				server.AddService(svc)
			}
		},
	}
	container := mockappcontainer.NewBuilder().WithDiscovery(discovery.New()).Container()
	srv, err := gserver.Start("echo", cfg, container, factories, opts...)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	addr := srv.(*gserver.Server).Listeners[0].Addr().String()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return srv, conn
}

func callEcho(ctx context.Context, conn *grpc.ClientConn, value []byte) ([]byte, error) {
	out := &wrapperspb.BytesValue{}
	if err := conn.Invoke(ctx, echoMethod, wrapperspb.Bytes(value), out); err != nil {
		return nil, err
	}
	return out.GetValue(), nil
}

// callWatch returns the values streamed by Watch until it ends.
func callWatch(ctx context.Context, conn *grpc.ClientConn, value string) ([]string, error) {
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, watchMethod)
	if err != nil {
		return nil, err
	}
	if err = stream.SendMsg(wrapperspb.Bytes([]byte(value))); err != nil {
		return nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, err
	}
	var got []string
	for {
		msg := &wrapperspb.BytesValue{}
		err = stream.RecvMsg(msg)
		if errors.Is(err, io.EOF) {
			return got, nil
		}
		if err != nil {
			return got, err
		}
		got = append(got, string(msg.GetValue()))
	}
}

// TestGRPCInterceptorChain checks that Start installs the request
// validation and panic interceptors before the built-in chain, and runs the
// interceptors added by options after it, with the caller identity set.
func TestGRPCInterceptorChain(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var unaryCalls, streamCalls []string
	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		mu.Lock()
		unaryCalls = append(unaryCalls, info.FullMethod+" "+identity.FromContext(ctx).Identity().Role())
		mu.Unlock()
		return handler(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		mu.Lock()
		streamCalls = append(streamCalls, info.FullMethod+" "+identity.FromContext(ss.Context()).Identity().Role())
		mu.Unlock()
		return handler(srv, ss)
	}
	svc := newEchoServer()
	_, conn := startEcho(t, &gserver.Config{}, svc,
		gserver.WithUnaryServerInterceptor(unary),
		gserver.WithStreamServerInterceptor(stream))
	ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
	defer cancel()

	got, err := callEcho(ctx, conn, []byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
	assert.Equal(t, int32(1), svc.calls.Load())

	// The validation interceptor rejects the request before the handler and
	// the option interceptors.
	_, err = callEcho(ctx, conn, []byte(echoInvalid))
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "invalid echo request", status.Convert(err).Message())
	assert.Equal(t, int32(1), svc.calls.Load())

	// A panic before the built-in chain is recovered by the outermost
	// interceptor, which fails the call with Internal.
	_, err = callEcho(ctx, conn, []byte(echoValidatePanic))
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, "unhandled exception", status.Convert(err).Message())

	// A panicking handler fails its call and the server keeps serving.
	_, err = callEcho(ctx, conn, []byte(echoPanic))
	require.Error(t, err)
	assert.Equal(t, "unhandled exception", status.Convert(err).Message())
	assert.Equal(t, int32(2), svc.calls.Load())
	got, err = callEcho(ctx, conn, []byte("after panic"))
	require.NoError(t, err)
	assert.Equal(t, "after panic", string(got))

	values, err := callWatch(ctx, conn, "tick")
	require.NoError(t, err)
	assert.Equal(t, []string{"tick", "tick", "tick"}, values)

	mu.Lock()
	defer mu.Unlock()
	guest := echoMethod + " " + roles.GuestRoleName
	assert.Equal(t, []string{guest, guest, guest}, unaryCalls)
	assert.Equal(t, []string{watchMethod + " " + roles.GuestRoleName}, streamCalls)
}

// TestGRPCMessageSizeLimits checks that the MaxRecvMsgSize and
// MaxSendMsgSize options bound gRPC messages and override the Config
// values.
func TestGRPCMessageSizeLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  gserver.Config
		opts []gserver.Option
		// request is sent to Echo; wantCode is the expected status code
		request  []byte
		wantCode codes.Code
	}{
		{
			name:     "config receive limit",
			cfg:      gserver.Config{MaxRecvMsgSize: messageSizeLimit},
			request:  make([]byte, largeMessageSize),
			wantCode: codes.ResourceExhausted,
		},
		{
			name:     "within config receive limit",
			cfg:      gserver.Config{MaxRecvMsgSize: messageSizeLimit},
			request:  make([]byte, smallMessageSize),
			wantCode: codes.OK,
		},
		{
			name:     "option receive limit",
			opts:     []gserver.Option{gserver.MaxRecvMsgSize(messageSizeLimit)},
			request:  make([]byte, largeMessageSize),
			wantCode: codes.ResourceExhausted,
		},
		{
			name:     "option overrides config receive limit",
			cfg:      gserver.Config{MaxRecvMsgSize: messageSizeLimit},
			opts:     []gserver.Option{gserver.MaxRecvMsgSize(2 * largeMessageSize)},
			request:  make([]byte, largeMessageSize),
			wantCode: codes.OK,
		},
		{
			name:     "config send limit",
			cfg:      gserver.Config{MaxSendMsgSize: messageSizeLimit},
			request:  []byte(echoLarge),
			wantCode: codes.ResourceExhausted,
		},
		{
			name:     "option send limit",
			opts:     []gserver.Option{gserver.MaxSendMsgSize(messageSizeLimit)},
			request:  []byte(echoLarge),
			wantCode: codes.ResourceExhausted,
		},
		{
			name:     "option overrides config send limit",
			cfg:      gserver.Config{MaxSendMsgSize: messageSizeLimit},
			opts:     []gserver.Option{gserver.MaxSendMsgSize(2 * largeMessageSize)},
			request:  []byte(echoLarge),
			wantCode: codes.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := tt.cfg
			_, conn := startEcho(t, &cfg, newEchoServer(), tt.opts...)
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()

			got, err := callEcho(ctx, conn, tt.request)
			require.Equal(t, tt.wantCode, status.Code(err), "err: %v", err)
			if tt.wantCode != codes.OK {
				return
			}
			if string(tt.request) == echoLarge {
				assert.Len(t, got, largeMessageSize)
			} else {
				assert.Equal(t, tt.request, got)
			}
		})
	}
}

// newGRPCMetricsSink installs a process-global in-memory metrics sink and
// returns a function that reports the count of every sample and counter
// key, summed over all intervals. Tests that call it must not run in
// parallel.
func newGRPCMetricsSink(t *testing.T) func() map[string]int {
	t.Helper()
	im := metrics.NewInmemSink(time.Minute, 5*time.Minute)
	mcfg := metrics.DefaultConfig(grpcMetricsName)
	// Runtime metrics would add samples to the exact comparison.
	mcfg.EnableRuntimeMetrics = false
	_, err := metrics.NewGlobal(mcfg, im)
	require.NoError(t, err)
	return func() map[string]int {
		counts := map[string]int{}
		for _, interval := range im.Data() {
			for k, v := range interval.Samples {
				counts[k] += v.Count
			}
			for k, v := range interval.Counters {
				counts[k] += v.Count
			}
		}
		return counts
	}
}

// rpcMetric returns the sample and counter keys of one gRPC call of api
// that ended with code, made by a guest.
func rpcMetric(api string, code codes.Code) map[string]int {
	labels := ";api=" + api + ";status=" + code.String()
	return map[string]int{
		grpcMetricsName + "_rpc_requests_perf" + labels:                                  1,
		grpcMetricsName + "_rpc_requests_role" + labels + ";role=" + roles.GuestRoleName: 1,
	}
}

// TestGRPCRequestMetrics checks the metrics recorded by the logging
// interceptors: one sample and one counter per call labelled with the
// method and the status code of its error, a single counter under "unknown"
// and "404" for NotFound, and nothing for a successful call on a skipped
// path. It installs the process-global metrics sink, so it is not parallel.
func TestGRPCRequestMetrics(t *testing.T) {
	counts := newGRPCMetricsSink(t)
	cfg := &gserver.Config{
		SkipLogPaths: []telemetry.LoggerSkipPath{
			{Path: watchMethod, Agent: "*"},
		},
	}
	_, conn := startEcho(t, cfg, newEchoServer())
	ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
	defer cancel()

	for _, tt := range []struct {
		value string
		code  codes.Code
	}{
		{"hello", codes.OK},
		{echoNotFound, codes.NotFound},
		{echoInternal, codes.Internal},
		{echoMany, codes.InvalidArgument},
		{echoStatus, codes.FailedPrecondition},
	} {
		_, err := callEcho(ctx, conn, []byte(tt.value))
		require.Equal(t, tt.code, status.Code(err), "%s: %v", tt.value, err)
	}
	// A skipped path records only failures.
	_, err := callWatch(ctx, conn, "tick")
	require.NoError(t, err)
	_, err = callWatch(ctx, conn, echoStatus)
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)

	want := map[string]int{
		grpcMetricsName + "_rpc_requests_role;api=unknown;status=404;role=" + roles.GuestRoleName: 1,
	}
	for _, m := range []map[string]int{
		rpcMetric(echoMethod, codes.OK),
		rpcMetric(echoMethod, codes.Internal),
		rpcMetric(echoMethod, codes.InvalidArgument),
		rpcMetric(echoMethod, codes.FailedPrecondition),
		rpcMetric(watchMethod, codes.FailedPrecondition),
	} {
		maps.Copy(want, m)
	}
	assert.Equal(t, want, counts())
}

// TestCloseStopsStreamsAfterRequestTimeout checks that Close waits up to
// Timeout.Request for active RPCs on plaintext and TLS listeners, then stops
// the gRPC server, which ends the remaining streams.
func TestCloseStopsStreamsAfterRequestTimeout(t *testing.T) {
	t.Parallel()
	// Closing a cmux child listener (GracefulStop on plaintext listeners,
	// http.Server.Shutdown on TLS ones) closes the root listener, so
	// cmux.Serve returns an error while Close drains; the setup cleanup of
	// serve must not stop the gRPC server then.
	tcases := []struct {
		name      string
		serverTLS *gserver.TLSInfo
	}{
		{name: "plaintext"},
		{name: "tls", serverTLS: &gserver.TLSInfo{
			CertFile:      "testdata/test-server.pem",
			KeyFile:       "testdata/test-server-key.pem",
			TrustedCAFile: "testdata/test-server-rootca.pem",
		}},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const requestTimeout = 200 * time.Millisecond
			cfg := &gserver.Config{ServerTLS: tc.serverTLS}
			cfg.Timeout.Request = requestTimeout
			svc := newEchoServer()
			srv, conn := startEcho(t, cfg, svc)
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()

			stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, blockMethod)
			require.NoError(t, err)
			require.NoError(t, stream.SendMsg(wrapperspb.Bytes(nil)))
			require.NoError(t, stream.CloseSend())
			select {
			case <-svc.blocked:
			case <-ctx.Done():
				t.Fatal("the Block stream did not start")
			}

			start := time.Now()
			srv.Close()
			elapsed := time.Since(start)
			assert.GreaterOrEqual(t, elapsed, requestTimeout, "Close must wait for the graceful stop first")
			assert.Less(t, elapsed, echoTimeout)

			err = stream.RecvMsg(&wrapperspb.BytesValue{})
			require.Error(t, err)
			if tc.serverTLS == nil {
				assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
			}
			// FINDINGS P-102: on TLS listeners the stream ends with a
			// malformed HTTP response, which the client reports as Unknown.
		})
	}
}
