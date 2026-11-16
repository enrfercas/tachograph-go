package card

import (
	"context"
	"crypto/rsa"
	"errors"

	"github.com/way-platform/tachograph-go/internal/cert"
	"github.com/way-platform/tachograph-go/internal/security"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
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
	Status   string
	Issues   []AuthenticityIssue
	Evidence *AuthenticationEvidence
}

// AssessAuthenticity shares the production chain/data verification operations.
// It never promotes missing trust or an unimplemented algorithm to INVALID.
func (o AuthenticateOptions) AssessAuthenticity(ctx context.Context, raw *cardv1.RawCardFile) AuthenticityAssessment {
	if o.CertificateResolver == nil {
		o.CertificateResolver = cert.DefaultResolver()
	}
	result := AuthenticityAssessment{Status: "VERIFIED", Issues: []AuthenticityIssue{}}
	encoded, err := (MarshalOptions{}).MarshalRawCardFile(raw)
	if err != nil {
		return AuthenticityAssessment{Status: "UNVERIFIED", Issues: []AuthenticityIssue{{Status: "UNVERIFIED", Reason: "verification_incomplete"}}}
	}
	hash := digest(encoded)
	o = o.bindTime(hash)
	result.Evidence = &AuthenticationEvidence{PolicyVersion: AuthenticationPolicyVersion, SHA256: hash, TemporalReference: o.TemporalEvidence, Certificates: []CertificateEvidence{}, Applications: []ApplicationEvidence{}, CryptographicStatus: "VERIFIED"}
	o.evidence = result.Evidence
	o.dataSignatures = map[int]string{}
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
		application := ApplicationEvidence{Application: generation.name, Profile: "RSA_SHA1", Status: "VERIFIED", CoveredTags: []int{}, DataSignatureStatus: "NOT_EVALUATED", CryptographicStatus: "VERIFIED"}
		if generation.name == "G2" {
			application.Profile = "ECDSA"
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
			if failure, ok := err.(*AuthenticationFailure); ok {
				if !temporalOnlyReason(failure.Reason) && rank[failure.Status] > rank[application.CryptographicStatus] {
					application.CryptographicStatus = failure.Status
				}
				result.Issues = append(result.Issues, AuthenticityIssue{Status: failure.Status, Reason: failure.Reason, Application: generation.name})
				if rank[failure.Status] > rank[result.Status] {
					result.Status = failure.Status
				}
				if rank[failure.Status] > rank[application.Status] {
					application.Status = failure.Status
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
			if application.Status == "VERIFIED" {
				application.Status = "UNVERIFIED"
			}
			if application.CryptographicStatus == "VERIFIED" {
				application.CryptographicStatus = "UNVERIFIED"
			}
		}
		collect(generation.verify())
		allVerified, anyInvalid, found := true, false, false
		for _, record := range raw.GetRecords() {
			name := "G1"
			if record.GetGeneration() == ddv1.Generation_GENERATION_2 {
				name = "G2"
			}
			if name != generation.name || record.GetContentType() != cardv1.ContentType_DATA || !isSignedEF(record.GetFile()) {
				continue
			}
			found = true
			status := o.dataSignatures[int(record.GetTag())]
			if status == "VALID" {
				application.CoveredTags = append(application.CoveredTags, int(record.GetTag()))
			} else {
				allVerified = false
			}
			anyInvalid = anyInvalid || status == "INVALID"
		}
		if found && allVerified {
			application.DataSignatureStatus = "VALID"
		} else if anyInvalid {
			application.DataSignatureStatus = "INVALID"
		}
		if !found || !allVerified && application.CryptographicStatus == "VERIFIED" {
			application.CryptographicStatus = "UNVERIFIED"
		}
		if rank[application.CryptographicStatus] > rank[result.Evidence.CryptographicStatus] {
			result.Evidence.CryptographicStatus = application.CryptographicStatus
		}
		result.Evidence.Applications = append(result.Evidence.Applications, application)
	}
	if !has1 && !has2 {
		result.Status = "UNVERIFIED"
		result.Evidence.CryptographicStatus = "UNVERIFIED"
		result.Issues = append(result.Issues, AuthenticityIssue{Status: "UNVERIFIED", Reason: "application_unknown"})
	}
	result.Evidence.Status = result.Status
	result.Evidence.summarizeTime()
	return result
}
