package card

import (
	"context"
	"crypto/rsa"
	"errors"

	"github.com/way-platform/tachograph-go/internal/cert"
	"github.com/way-platform/tachograph-go/internal/security"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
)

// AuthenticationFailure retains a stable, non-personal reason independently of
// acquisition. The cause remains available internally through errors.Unwrap.
type AuthenticationFailure struct {
	Status, Reason string
	cause          error
}

func (e *AuthenticationFailure) Error() string { return e.Reason }
func (e *AuthenticationFailure) Unwrap() error { return e.cause }
func authFailure(status, reason string, err error) error {
	return &AuthenticationFailure{Status: status, Reason: reason, cause: err}
}
func signatureFailure(reason string, err error) error {
	var unsupported *security.UnsupportedAlgorithmError
	if errors.As(err, &unsupported) {
		return authFailure("UNVERIFIED", "algorithm_unsupported", err)
	}
	var invalid *security.InvalidSignatureError
	if errors.As(err, &invalid) || errors.Is(err, rsa.ErrVerification) {
		return authFailure("INVALID", reason, err)
	}
	return authFailure("UNVERIFIED", "crypto_capability_or_encoding_unavailable", err)
}

type AuthenticityIssue struct {
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Application string `json:"application"`
}
type AuthenticityAssessment struct {
	Status string
	Issues []AuthenticityIssue
}

// AssessAuthenticity shares the production chain/data verification operations.
// It never promotes missing trust or an unimplemented algorithm to INVALID.
func (o AuthenticateOptions) AssessAuthenticity(ctx context.Context, raw *cardv1.RawCardFile) AuthenticityAssessment {
	if o.CertificateResolver == nil {
		o.CertificateResolver = cert.DefaultResolver()
	}
	result := AuthenticityAssessment{Status: "VERIFIED", Issues: []AuthenticityIssue{}}
	has1, has2 := o.detectGenerations(raw)
	rank := map[string]int{"VERIFIED": 0, "UNVERIFIED": 1, "MISSING": 2, "INVALID": 3}
	for _, generation := range []struct {
		present bool
		name    string
		verify  func() error
	}{{has1, "G1", func() error { return o.authenticateGen1CardFile(ctx, raw) }}, {has2, "G2", func() error { return o.authenticateGen2CardFile(ctx, raw) }}} {
		if !generation.present {
			continue
		}
		var collect func(error)
		collect = func(err error) {
			if err == nil {
				return
			}
			if many, ok := err.(interface{ Unwrap() []error }); ok {
				for _, child := range many.Unwrap() {
					collect(child)
				}
				return
			}
			var failure *AuthenticationFailure
			if errors.As(err, &failure) {
				result.Issues = append(result.Issues, AuthenticityIssue{Status: failure.Status, Reason: failure.Reason, Application: generation.name})
				if rank[failure.Status] > rank[result.Status] {
					result.Status = failure.Status
				}
				return
			}
			if child := errors.Unwrap(err); child != nil {
				collect(child)
				return
			}
			result.Issues = append(result.Issues, AuthenticityIssue{Status: "UNVERIFIED", Reason: "verification_incomplete", Application: generation.name})
			if result.Status == "VERIFIED" {
				result.Status = "UNVERIFIED"
			}
		}
		collect(generation.verify())
	}
	if !has1 && !has2 {
		result.Status = "UNVERIFIED"
		result.Issues = append(result.Issues, AuthenticityIssue{Status: "UNVERIFIED", Reason: "application_unknown"})
	}
	return result
}
