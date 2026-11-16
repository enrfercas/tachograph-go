package card

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/way-platform/tachograph-go/internal/security"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

const AuthenticationPolicyVersion = "card-authentication-2026-11-13/f04-time-v2"

// TemporalEvidence is a reference supplied by the acquisition owner, never the
// analysis clock or a date read from activities, card expiry or file metadata.
// A local acquisition window is not an independently timestamped signature.
type TemporalEvidence struct {
	SHA256 string    `json:"sha256"`
	Kind   string    `json:"kind"`
	Source string    `json:"source"`
	Start  time.Time `json:"startUtc"`
	End    time.Time `json:"endUtc"`
}

type CertificateEvidence struct {
	Application         string     `json:"application"`
	Role                string     `json:"role"`
	SHA256              string     `json:"sha256"`
	CAR                 string     `json:"car"`
	CHR                 string     `json:"chr"`
	CHA                 string     `json:"cha"`
	SignatureStatus     string     `json:"signatureStatus"`
	AuthorizationStatus string     `json:"authorizationStatus"`
	TemporalStatus      string     `json:"temporalStatus"`
	EffectiveUTC        *time.Time `json:"effectiveUtc,omitempty"`
	ExpirationUTC       *time.Time `json:"expirationUtc,omitempty"`
}

type AuthenticationEvidence struct {
	PolicyVersion        string                `json:"policyVersion"`
	SHA256               string                `json:"sha256"`
	TemporalReference    *TemporalEvidence     `json:"temporalReference,omitempty"`
	IndependentTimestamp bool                  `json:"independentTimestamp"`
	Certificates         []CertificateEvidence `json:"certificates"`
	Applications         []ApplicationEvidence `json:"applications"`
	Status               string                `json:"status"`
	// VERIFIED here covers signatures, chain and CHA, not historical time.
	CryptographicStatus string `json:"cryptographicStatus"`
	TemporalStatus      string `json:"temporalStatus"`
}

type ApplicationEvidence struct {
	Application         string `json:"application"`
	Profile             string `json:"profile"`
	CoveredTags         []int  `json:"coveredTags"`
	DataSignatureStatus string `json:"dataSignatureStatus"`
	Status              string `json:"status"`
	CryptographicStatus string `json:"cryptographicStatus"`
}

// HasOnlyUnevaluatedTime requires explicit current cryptographic proof. It never
// promotes legacy evidence, a missing chain, or a demonstrated validity defect.
func (e *AuthenticationEvidence) HasOnlyUnevaluatedTime() bool {
	if e == nil || e.PolicyVersion != AuthenticationPolicyVersion || e.Status != "UNVERIFIED" || e.CryptographicStatus != "VERIFIED" || e.TemporalStatus != "NOT_EVALUATED" || len(e.Certificates) == 0 || len(e.Applications) == 0 {
		return false
	}
	unknown := false
	for _, c := range e.Certificates {
		if c.AuthorizationStatus != "VALID" || c.SignatureStatus != "VALID" && c.SignatureStatus != "TRUST_ANCHOR" {
			return false
		}
		switch c.TemporalStatus {
		case "UNKNOWN_REFERENCE", "BOUNDARY_UNCERTAIN":
			unknown = true
		case "VALID_AT_REFERENCE", "NOT_USED":
		default:
			return false
		}
	}
	for _, a := range e.Applications {
		if a.CryptographicStatus != "VERIFIED" || a.DataSignatureStatus != "VALID" || len(a.CoveredTags) == 0 {
			return false
		}
	}
	return unknown
}

func temporalOnlyReason(reason string) bool {
	switch reason {
	case "historical_time_unproven", "temporal_evidence_digest_mismatch", "temporal_reference_invalid", "acquisition_crosses_validity_boundary", "certificate_outside_validity":
		return true
	default:
		return false
	}
}

func (e *AuthenticationEvidence) summarizeTime() {
	e.TemporalStatus = "NOT_APPLICABLE"
	unknown, applicable := len(e.Certificates) == 0, false
	for _, c := range e.Certificates {
		switch c.TemporalStatus {
		case "MALFORMED", "OUTSIDE_VALIDITY":
			e.TemporalStatus = "INVALID"
			return
		case "UNKNOWN_REFERENCE", "BOUNDARY_UNCERTAIN":
			unknown = true
		case "VALID_AT_REFERENCE":
			applicable = true
		}
	}
	if unknown {
		e.TemporalStatus = "NOT_EVALUATED"
	} else if applicable {
		e.TemporalStatus = "VALID"
	}
}

// policyFailure permits mathematical EF verification to continue after a
// demonstrated CHA/validity defect or temporal uncertainty in an authentic chain.
type policyFailure struct{ error }

func (e *policyFailure) Unwrap() error { return e.error }
func policyFailures(errs ...error) error {
	err := errors.Join(errs...)
	if err == nil {
		return nil
	}
	return &policyFailure{err}
}

func (o AuthenticateOptions) checkCertificate(e CertificateEvidence, cha, aid []byte, role byte, start, end *time.Time, unused bool, malformed bool) error {
	e.CHA = hex.EncodeToString(cha)
	e.AuthorizationStatus = "VALID"
	e.EffectiveUTC, e.ExpirationUTC = start, end
	var errs []error
	if len(cha) != 7 || !bytes.Equal(cha[:min(6, len(cha))], aid) || cha[6] != role {
		e.AuthorizationStatus = "INVALID"
		errs = append(errs, authFailure("INVALID", "certificate_authorization_invalid", nil))
	}
	switch {
	case malformed || !unused && (end == nil || start != nil && !start.Before(*end)):
		e.TemporalStatus = "MALFORMED"
		errs = append(errs, authFailure("INVALID", "certificate_validity_malformed", nil))
	case unused:
		e.TemporalStatus = "NOT_USED"
	case o.TemporalEvidence == nil:
		e.TemporalStatus = "UNKNOWN_REFERENCE"
		reason := "historical_time_unproven"
		if o.temporalReason != "" {
			reason = o.temporalReason
		}
		errs = append(errs, authFailure("UNVERIFIED", reason, nil))
	default:
		t := o.TemporalEvidence
		switch {
		case !t.Start.Before(*end) || start != nil && t.End.Before(*start):
			e.TemporalStatus = "OUTSIDE_VALIDITY"
			errs = append(errs, authFailure("INVALID", "certificate_outside_validity", nil))
		case !t.End.Before(*end) || start != nil && t.Start.Before(*start):
			e.TemporalStatus = "BOUNDARY_UNCERTAIN"
			errs = append(errs, authFailure("UNVERIFIED", "acquisition_crosses_validity_boundary", nil))
		default:
			e.TemporalStatus = "VALID_AT_REFERENCE"
		}
	}
	if o.evidence != nil {
		o.evidence.Certificates = append(o.evidence.Certificates, e)
	}
	return errors.Join(errs...)
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (o AuthenticateOptions) checkRsa(cert *securityv1.RsaCertificate, modulus, exponent []byte, issuer, roleName string, role byte) error {
	cha, end, err := security.RsaPolicyFields(cert, modulus, exponent, issuer)
	if err != nil {
		return authFailure("INVALID", "certificate_profile_or_reference_invalid", err)
	}
	var expiration *time.Time
	if end != 0xffffffff && end != 0 {
		t := time.Unix(int64(end), 0).UTC()
		expiration = &t
	}
	return o.checkCertificate(CertificateEvidence{Application: "G1", Role: roleName, SHA256: digest(cert.GetRawData()), CAR: cert.GetCertificateAuthorityReference(), CHR: cert.GetCertificateHolderReference(), SignatureStatus: "VALID"}, cha, []byte{0xff, 0x54, 0x41, 0x43, 0x48, 0x4f}, role, nil, expiration, end == 0xffffffff, end == 0)
}

func (o AuthenticateOptions) checkEcc(cert *securityv1.EccCertificate, roleName string, role byte) error {
	var start, end *time.Time
	if t := cert.GetCertificateEffectiveDate(); t != nil && t.CheckValid() == nil {
		v := t.AsTime().UTC()
		start = &v
	}
	if t := cert.GetCertificateExpirationDate(); t != nil && t.CheckValid() == nil {
		v := t.AsTime().UTC()
		end = &v
	}
	sig := "VALID"
	if roleName == "ERCA" {
		sig = "TRUST_ANCHOR"
	}
	return o.checkCertificate(CertificateEvidence{Application: "G2", Role: roleName, SHA256: digest(cert.GetRawData()), CAR: cert.GetCertificateAuthorityReference(), CHR: cert.GetCertificateHolderReference(), SignatureStatus: sig}, cert.GetCertificateHolderAuthorisation(), []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54}, role, start, end, false, start == nil || cert.GetCertificateProfileIdentifier() != 0)
}

func (o AuthenticateOptions) bindTime(hash string) AuthenticateOptions {
	t := o.TemporalEvidence
	if t == nil {
		return o
	}
	if t.SHA256 != hash {
		o.temporalReason = "temporal_evidence_digest_mismatch"
	} else if t.Source == "" || (t.Kind != "ACQUISITION_WINDOW" && t.Kind != "SIGNATURE_INSTANT") || t.Start.IsZero() || t.End.IsZero() || t.End.Before(t.Start) || t.Kind == "SIGNATURE_INSTANT" && !t.Start.Equal(t.End) {
		o.temporalReason = "temporal_reference_invalid"
	}
	if o.temporalReason != "" {
		o.TemporalEvidence = nil
	}
	return o
}
