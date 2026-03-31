package server

import (
	"context"
	"errors"

	"github.com/rajanyadav/promptlock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GRPCService implements the PromptLock gRPC service.
type GRPCService struct {
	shield *promptlock.Shield
}

// NewGRPCService creates a gRPC service wrapping the given Shield.
func NewGRPCService(shield *promptlock.Shield) *GRPCService {
	return &GRPCService{shield: shield}
}

// RegisterWith registers this service on the given gRPC server.
func (s *GRPCService) RegisterWith(srv *grpc.Server) {
	// Registration is done manually since we're not using protoc-generated code.
	// Users who generate code from the .proto can use the generated registration.
	// For now, this service is exposed via the REST API.
	_ = srv
}

// --- gRPC-compatible request/response types ---
// These mirror the protobuf messages but are plain Go structs.
// They are used by the gRPC service and can also be used directly.

// ProtectRPC handles the Protect RPC call.
func (s *GRPCService) ProtectRPC(ctx context.Context, input string) (*protectResponse, error) {
	output, err := s.shield.Protect(ctx, input)
	if err != nil {
		var plErr *promptlock.PromptLockError
		if errors.As(err, &plErr) {
			return &protectResponse{
				Blocked:    true,
				Score:      plErr.Score,
				Verdict:    plErr.Verdict.String(),
				Violations: mapViolations(plErr.Violations),
			}, nil
		}
		return nil, status.Errorf(codes.Internal, "protect: %v", err)
	}

	return &protectResponse{
		Output:  output,
		Blocked: false,
		Verdict: "clean",
	}, nil
}

// ProtectWithResultRPC handles the ProtectWithResult RPC call.
func (s *GRPCService) ProtectWithResultRPC(ctx context.Context, input string) (*scanResultResponse, error) {
	result, err := s.shield.ProtectWithResult(ctx, input)
	if err != nil {
		var plErr *promptlock.PromptLockError
		if errors.As(err, &plErr) {
			return &scanResultResponse{
				Clean:      false,
				Score:      plErr.Score,
				Verdict:    plErr.Verdict.String(),
				Violations: mapViolations(plErr.Violations),
				Redactions: []redactedEntityResponse{},
			}, nil
		}
		return nil, status.Errorf(codes.Internal, "protect: %v", err)
	}

	return &scanResultResponse{
		Output:     result.Output,
		Clean:      result.Clean,
		Score:      result.Score,
		Verdict:    result.Verdict.String(),
		Violations: mapViolations(result.Violations),
		Redactions: mapRedactions(result.Redactions),
		Delimiter:  result.Delimiter,
		LatencyMs:  result.Latency.Milliseconds(),
	}, nil
}

// VerifyContextRPC handles the VerifyContext RPC call.
func (s *GRPCService) VerifyContextRPC(ctx context.Context, chunks []string) (*verifyContextResponse, error) {
	clean, err := s.shield.VerifyContext(ctx, chunks)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "verify context: %v", err)
	}

	return &verifyContextResponse{
		CleanChunks:  clean,
		BlockedCount: len(chunks) - len(clean),
	}, nil
}
