package tachograph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/way-platform/tachograph-go/internal/security"
	"github.com/way-platform/tachograph-go/internal/testcard"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

func cardTestTime(f *testcard.Fixture) *CardTemporalEvidence {
	h := sha256.Sum256(f.Bytes())
	t := time.Unix(1700000000, 0).UTC()
	return &CardTemporalEvidence{SHA256: hex.EncodeToString(h[:]), Kind: "ACQUISITION_WINDOW", Source: "LOCAL_SYSTEM_CLOCK", Start: t, End: t.Add(time.Minute)}
}

func TestCardPolicyRejectsSignedIncompatibleCHA(t *testing.T) {
	for _, gen := range []string{"G1", "G2V1", "G2V2"} {
		for _, tc := range []struct {
			name   string
			tag    int
			cha    []byte
			rotate bool
		}{
			{"g1CardRole", 0xc10000, []byte{0xff, 0x54, 0x41, 0x43, 0x48, 0x4f, 2}, false},
			{"g1CardAID", 0xc10000, []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54, 1}, false},
			{"g1MSCA", 0xc10800, []byte{0xff, 0x54, 0x41, 0x43, 0x48, 0x4f, 1}, false},
			{"cardMA", 0xc10102, []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54, 1}, false},
			{"g2AID", 0xc10102, []byte{0xff, 0x54, 0x41, 0x43, 0x48, 0x4f, 0x11}, false},
			{"g2MSCA", 0xc10802, []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54, 0x11}, false},
			{"rootLink", 0xc10902, []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54, 0x0e}, true},
		} {
			if gen == "G1" && tc.tag&2 != 0 {
				continue
			}
			t.Run(gen+"/"+tc.name, func(t *testing.T) {
				f, err := testcard.New(gen)
				if err != nil {
					t.Fatal(err)
				}
				if tc.rotate {
					if err := f.RotateRoot(); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.ReissueCertificate(tc.tag, tc.cha, 1, 2208988800); err != nil {
					t.Fatal(err)
				}
				r, err := (CardDownloadValidationOptions{ExpectedGeneration: gen, CertificateResolver: f}).Validate(context.Background(), f.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				if r.AuthenticityStatus != AuthenticityInvalid {
					t.Fatalf("signed incompatible CHA accepted: %s %+v", r.AuthenticityStatus, r.Issues)
				}
			})
		}
	}
}

func TestCardPolicyUnknownHistoricalTimeIsNotVerified(t *testing.T) {
	for _, gen := range []string{"G1", "G2V1", "G2V2"} {
		f, err := testcard.New(gen)
		if err != nil {
			t.Fatal(err)
		}
		if gen == "G1" {
			if err := f.ReissueCertificate(0xc10000, []byte{0xff, 0x54, 0x41, 0x43, 0x48, 0x4f, 1}, 0, 1700000000); err != nil {
				t.Fatal(err)
			}
		}
		r, err := (CardDownloadValidationOptions{ExpectedGeneration: gen, CertificateResolver: f}).Validate(context.Background(), f.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if r.AuthenticityStatus != AuthenticityUnverified {
			t.Fatalf("%s historical time invented: %s", gen, r.AuthenticityStatus)
		}
	}
}

func TestCardPolicyHistoricalValidityAndEvidence(t *testing.T) {
	for _, gen := range []string{"G1", "G2V1", "G2V2"} {
		for _, tc := range []struct {
			name             string
			start, end       uint32
			refStart, refEnd int64
			unknown          bool
			status           AuthenticityStatus
			temporal         string
		}{
			{"historicalValidNowExpired", 1500000000, 1600000000, 1550000000, 1550000060, false, AuthenticityVerified, "VALID_AT_REFERENCE"},
			{"expiredAtReference", 1500000000, 1600000000, 1650000000, 1650000060, false, AuthenticityInvalid, "OUTSIDE_VALIDITY"},
			{"notYetValid", 1700000000, 1800000000, 1650000000, 1650000060, false, AuthenticityInvalid, "OUTSIDE_VALIDITY"},
			{"expirationBoundary", 1500000000, 1600000000, 1599999990, 1600000010, false, AuthenticityUnverified, "BOUNDARY_UNCERTAIN"},
			{"effectiveBoundary", 1500000000, 1600000000, 1499999990, 1500000010, false, AuthenticityUnverified, "BOUNDARY_UNCERTAIN"},
			{"unknownHistorical", 1500000000, 1600000000, 0, 0, true, AuthenticityUnverified, "UNKNOWN_REFERENCE"},
			{"malformed", 1500000000, 0, 1550000000, 1550000060, false, AuthenticityInvalid, "MALFORMED"},
		} {
			if gen == "G1" && (tc.name == "notYetValid" || tc.name == "effectiveBoundary") {
				continue
			} // G1 has no start date.
			t.Run(gen+"/"+tc.name, func(t *testing.T) {
				f, err := testcard.New(gen)
				if err != nil {
					t.Fatal(err)
				}
				tag, cha := 0xc10000, []byte{0xff, 0x54, 0x41, 0x43, 0x48, 0x4f, 1}
				if gen != "G1" {
					tag, cha = 0xc10102, []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54, 0x11}
				}
				if err := f.ReissueCertificate(tag, cha, tc.start, tc.end); err != nil {
					t.Fatal(err)
				}
				reference := cardTestTime(f)
				reference.Start, reference.End = time.Unix(tc.refStart, 0).UTC(), time.Unix(tc.refEnd, 0).UTC()
				if tc.unknown {
					reference = nil
				}
				b := f.Bytes()
				r, err := (CardDownloadValidationOptions{ExpectedGeneration: gen, CertificateResolver: f, TemporalEvidence: reference}).Validate(context.Background(), b)
				if err != nil || r.AuthenticityStatus != tc.status {
					t.Fatalf("%s: %+v %v", r.AuthenticityStatus, r.Issues, err)
				}
				e := r.AuthenticationEvidence
				if e == nil || e.PolicyVersion != CardAuthenticationPolicyVersion || e.SHA256 != r.SHA256 || e.IndependentTimestamp {
					t.Fatal("missing or overstated policy provenance")
				}
				found := false
				for _, c := range e.Certificates {
					if c.Role == "CARD" && gen == "G1" || c.Role == "CARD_SIGN" && gen != "G1" {
						found = true
						if c.TemporalStatus != tc.temporal || c.AuthorizationStatus != "VALID" || c.SignatureStatus != "VALID" {
							t.Fatalf("certificate evidence: %+v", c)
						}
					}
				}
				if !found {
					t.Fatal("missing certificate evidence")
				}
				for _, a := range e.Applications {
					if a.DataSignatureStatus != "VALID" || len(a.CoveredTags) == 0 {
						t.Fatalf("mathematical verification skipped for uncertainty/defect: %+v", a)
					}
				}
				raw, err := Unmarshal(b)
				if err != nil {
					t.Fatal(err)
				}
				_, authErr := (AuthenticateOptions{CertificateResolver: f, TemporalEvidence: reference}).Authenticate(context.Background(), raw)
				if (authErr == nil) != (tc.status == AuthenticityVerified) {
					t.Fatalf("historical Authenticate disagrees: %v", authErr)
				}
				if r.Inspection.AuthenticityStatus != string(tc.status) {
					t.Fatal("inspection disagrees")
				}
			})
		}
	}
}

func TestCardPolicyReferenceBindingAndBothApplications(t *testing.T) {
	for _, gen := range []string{"G2V1", "G2V2"} {
		for _, name := range []string{"validBoth", "badG1", "badG2", "unknownTimeBadSignature", "wrongDigest", "reversedWindow", "instant", "unusedZeroLink", "validLink", "badLink"} {
			t.Run(gen+"/"+name, func(t *testing.T) {
				f, err := testcard.New(gen)
				if err != nil {
					t.Fatal(err)
				}
				want := AuthenticityVerified
				switch name {
				case "badG1":
					f.Signatures[0x050100][0] ^= 1
					want = AuthenticityInvalid
				case "badG2", "unknownTimeBadSignature":
					f.Signatures[0x050102][0] ^= 1
					want = AuthenticityInvalid
				case "unusedZeroLink":
					f.Files[0xc10902] = make([]byte, 204)
				case "validLink", "badLink":
					if err := f.RotateRoot(); err != nil {
						t.Fatal(err)
					}
					if name == "badLink" {
						b := f.Files[0xc10902]
						b[len(b)-1] ^= 1
						want = AuthenticityInvalid
					}
				}
				ref := cardTestTime(f)
				switch name {
				case "wrongDigest":
					ref.SHA256 = "other"
					want = AuthenticityUnverified
				case "reversedWindow":
					ref.End = ref.Start.Add(-time.Second)
					want = AuthenticityUnverified
				case "instant":
					ref.Kind = "SIGNATURE_INSTANT"
					ref.End = ref.Start
				case "unknownTimeBadSignature":
					ref = nil
				}
				r, err := (CardDownloadValidationOptions{ExpectedGeneration: gen, CertificateResolver: f, TemporalEvidence: ref}).Validate(context.Background(), f.Bytes())
				if err != nil || r.AuthenticityStatus != want {
					t.Fatalf("got %s: %+v %v", r.AuthenticityStatus, r.Issues, err)
				}
				if len(r.AuthenticationEvidence.Applications) != 2 {
					t.Fatal("one application hidden")
				}
			})
		}
	}
}

func TestCardPolicyDriverExpiryDoesNotReplaceCardSignExpiry(t *testing.T) {
	for _, gen := range []string{"G2V1", "G2V2"} {
		f, err := testcard.New(gen)
		if err != nil {
			t.Fatal(err)
		}
		const reference = int64(1700000000)
		if err := f.SetCardExpiry(uint32(reference - 20*86400)); err != nil {
			t.Fatal(err)
		}
		if err := f.ReissueCertificate(0xc10102, []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54, 0x11}, uint32(reference-5*365*86400), uint32(reference+10*86400)); err != nil {
			t.Fatal(err)
		}
		o := CardDownloadValidationOptions{ExpectedGeneration: gen, CertificateResolver: f, TemporalEvidence: cardTestTime(f)}
		r, err := o.Validate(context.Background(), f.Bytes())
		if err != nil || r.AuthenticityStatus != AuthenticityVerified {
			t.Fatalf("administrative card expiry rejected valid CardSign: %+v %v", r.Issues, err)
		}
	}
}

func TestCardPolicyUnknownTrustAndIncompleteCertificateNeverVerified(t *testing.T) {
	for _, gen := range []string{"G1", "G2V1", "G2V2"} {
		for _, name := range []string{"unknownRoot", "incompleteRSA", "badRSA", "incompleteECC"} {
			if gen == "G1" && name == "incompleteECC" {
				continue
			}
			t.Run(gen+"/"+name, func(t *testing.T) {
				f, err := testcard.New(gen)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "unknownRoot":
					f.RsaRoot.SetKeyId("999")
					f.EccRoot.SetCertificateHolderReference("999")
				case "incompleteRSA":
					f.Files[0xc10000] = f.Files[0xc10000][:193]
				case "badRSA":
					f.Files[0xc10000][0] ^= 1
				case "incompleteECC":
					b := f.Files[0xc10102]
					f.Files[0xc10102] = b[:len(b)-1]
				}
				r, err := (CardDownloadValidationOptions{ExpectedGeneration: gen, CertificateResolver: f, TemporalEvidence: cardTestTime(f)}).Validate(context.Background(), f.Bytes())
				if err != nil || r.AuthenticityStatus == AuthenticityVerified {
					t.Fatalf("certificate defect accepted: %+v %v", r, err)
				}
				if name == "badRSA" && r.AuthenticityStatus != AuthenticityInvalid {
					t.Fatalf("demonstrated RSA defect became uncertainty: %+v", r.Issues)
				}
			})
		}
	}
}

func TestCardPolicyUncertaintyDoesNotLeaveVerifiedRawBlocks(t *testing.T) {
	f, err := testcard.New("G2V2")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Unmarshal(f.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (AuthenticateOptions{Mutate: true, CertificateResolver: f, TemporalEvidence: cardTestTime(f)}).Authenticate(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := (AuthenticateOptions{Mutate: true, CertificateResolver: f}).Authenticate(context.Background(), raw); err == nil {
		t.Fatal("unknown historical time authenticated")
	}
	for _, r := range raw.GetCard().GetRecords() {
		if r.GetGeneration() == ddv1.Generation_GENERATION_2 && r.GetAuthentication().GetStatus() == securityv1.Authentication_VERIFIED {
			t.Fatal("previous VERIFIED survived failed certificate policy")
		}
	}
}

func TestCardPolicyG1UnusedEOVNeedsNoInventedReference(t *testing.T) {
	f, err := testcard.New("G1")
	if err != nil {
		t.Fatal(err)
	}
	r, err := (CardDownloadValidationOptions{ExpectedGeneration: "G1", CertificateResolver: f}).Validate(context.Background(), f.Bytes())
	if err != nil || r.AuthenticityStatus != AuthenticityVerified {
		t.Fatalf("normative unused EOV rejected: %+v %v", r.Issues, err)
	}
	for _, c := range r.AuthenticationEvidence.Certificates {
		if c.TemporalStatus != "NOT_USED" || c.EffectiveUTC != nil || c.ExpirationUTC != nil {
			t.Fatalf("invented G1 dates: %+v", c)
		}
	}
}

func TestCardPolicyG2IssuersAndRequiredLink(t *testing.T) {
	for _, gen := range []string{"G2V1", "G2V2"} {
		for _, name := range []string{"rootCHA", "rootExpired", "mscaExpired", "mscaUndefinedStart", "cardReversedDates", "linkExpired"} {
			t.Run(gen+"/"+name, func(t *testing.T) {
				f, err := testcard.New(gen)
				if err != nil {
					t.Fatal(err)
				}
				tag, role, start, end := 0xc10802, byte(0x0e), uint32(1), uint32(1600000000)
				switch name {
				case "rootCHA":
					tag, role, end = 0xc10902, 0x0e, 2208988800
				case "rootExpired":
					tag, role = 0xc10902, 0x0d
				case "mscaUndefinedStart":
					start, end = 0, 2208988800
				case "cardReversedDates":
					tag, role, start, end = 0xc10102, 0x11, 1800000000, 1700000000
				case "linkExpired":
					if err := f.RotateRoot(); err != nil {
						t.Fatal(err)
					}
					tag, role = 0xc10902, 0x0d
				}
				if err := f.ReissueCertificate(tag, []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54, role}, start, end); err != nil {
					t.Fatal(err)
				}
				if name == "rootCHA" || name == "rootExpired" {
					f.EccRoot, err = security.UnmarshalEccCertificate(f.Files[tag])
					if err != nil {
						t.Fatal(err)
					}
				}
				r, err := (CardDownloadValidationOptions{ExpectedGeneration: gen, CertificateResolver: f, TemporalEvidence: cardTestTime(f)}).Validate(context.Background(), f.Bytes())
				if err != nil || r.AuthenticityStatus != AuthenticityInvalid {
					t.Fatalf("issuer policy defect accepted: %s %+v %v", r.AuthenticityStatus, r.Issues, err)
				}
			})
		}
	}
}
