package tachograph

import (
	"bytes"
	"context"
	"errors"
	"github.com/way-platform/tachograph-go/internal/card"
	"testing"

	"github.com/way-platform/tachograph-go/internal/testcard"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

type noLocalTrust struct{ CertificateResolver }

func (noLocalTrust) GetRootCertificate(context.Context) (*securityv1.RootCertificate, error) {
	return nil, errors.New("test trust unavailable")
}
func (noLocalTrust) GetEccRootCertificate(context.Context) (*securityv1.EccCertificate, error) {
	return nil, errors.New("test trust unavailable")
}

func TestAppendix7ConditionalEFsAndTrust(t *testing.T) {
	for _, test := range []struct {
		name      string
		modify    func(*testcard.Fixture)
		trust     string
		acq       AcquisitionStatus
		structure StructuralStatus
		auth      AuthenticityStatus
	}{
		{"without0540", func(f *testcard.Fixture) { delete(f.Files, 0x054002); delete(f.Signatures, 0x054002) }, "test", AcquisitionComplete, StructureValid, AuthenticityVerified},
		{"with0540", func(*testcard.Fixture) {}, "test", AcquisitionComplete, StructureValid, AuthenticityVerified},
		{"unusedZeroLink", func(f *testcard.Fixture) { f.Files[0xc10902] = make([]byte, 204) }, "test", AcquisitionComplete, StructureValid, AuthenticityVerified},
		{"withoutConditionalEFs", func(f *testcard.Fixture) {
			for _, fid := range []int{0x0525, 0x0526, 0x0527, 0x0528, 0x0529, 0x0530} {
				delete(f.Files, fid<<8|2)
				delete(f.Signatures, fid<<8|2)
			}
		}, "test", AcquisitionComplete, StructureValid, AuthenticityVerified},
		{"missingRequiredEF", func(f *testcard.Fixture) { delete(f.Files, 0x050202); delete(f.Signatures, 0x050202) }, "test", AcquisitionIncomplete, StructureInvalid, AuthenticityUnverified},
		{"truncatedPresentConditional", func(f *testcard.Fixture) { f.Files[0x052902] = f.Files[0x052902][:32481] }, "test", AcquisitionIncomplete, StructureInvalid, AuthenticityUnverified},
		{"missingSignature", func(f *testcard.Fixture) { delete(f.Signatures, 0x052802) }, "test", AcquisitionIncomplete, StructureInvalid, AuthenticityMissing},
		{"historicalCardDownloadExtra", func(f *testcard.Fixture) {
			f.Files[0x050e00] = make([]byte, 4)
			f.Signatures[0x050e00] = make([]byte, 128)
		}, "test", AcquisitionFailed, StructureUnsupported, AuthenticityUnverified},
		{"invalidSignature", func(f *testcard.Fixture) { f.Signatures[0x052802][0] ^= 1 }, "test", AcquisitionComplete, StructureValid, AuthenticityInvalid},
		{"trustUnavailable", func(*testcard.Fixture) {}, "missing", AcquisitionComplete, StructureValid, AuthenticityUnverified},
		{"unsupportedAlgorithm", func(f *testcard.Fixture) { f.EccRoot.GetPublicKey().SetDomainParametersOid("1.3.6.1.4.1.99999") }, "test", AcquisitionComplete, StructureValid, AuthenticityUnverified},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, err := testcard.New("G2V2")
			if err != nil {
				t.Fatal(err)
			}
			test.modify(f)
			var resolver CertificateResolver = f
			if test.trust == "missing" {
				resolver = noLocalTrust{f}
			}
			input := f.Bytes()
			original := bytes.Clone(input)
			result, err := (CardDownloadValidationOptions{ExpectedGeneration: "G2V2", CertificateResolver: resolver, ObservedCard: true}).Validate(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if result.AcquisitionStatus != test.acq || result.StructuralStatus != test.structure || result.AuthenticityStatus != test.auth {
				t.Fatalf("statuses %s/%s/%s, want %s/%s/%s", result.AcquisitionStatus, result.StructuralStatus, result.AuthenticityStatus, test.acq, test.structure, test.auth)
			}
			if !bytes.Equal(original, input) {
				t.Fatal("validation modified original bytes")
			}
			if test.name == "withoutConditionalEFs" && result.PhysicalCompleteness != "EXPECTED_FILES_NOT_FOUND" {
				t.Fatal("physical anomaly hidden")
			}
			if test.name == "trustUnavailable" || test.name == "unsupportedAlgorithm" {
				code := "erca_material_unavailable"
				if test.name == "unsupportedAlgorithm" {
					code = "algorithm_unsupported"
				}
				found := false
				for _, issue := range result.Issues {
					found = found || issue.Code == code
				}
				if !found {
					t.Fatal("unverified cause lost")
				}
			}
		})
	}
}

func TestUnknownEFIsUnsupportedAndRetained(t *testing.T) {
	f, err := testcard.New("G2V2")
	if err != nil {
		t.Fatal(err)
	}
	input := append(f.Bytes(), []byte{0x65, 0, 2, 0, 3, 0xfe, 0x33, 0x10}...)
	raw, err := (UnmarshalOptions{}).Unmarshal(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := (card.MarshalOptions{}).MarshalRawCardFile(raw.GetCard())
	if err != nil || !bytes.Equal(encoded, input) {
		t.Fatal("unknown raw EF lost", err)
	}
	result, err := (CardDownloadValidationOptions{ExpectedGeneration: "G2V2", CertificateResolver: f}).Validate(context.Background(), input)
	if err != nil || result.StructuralStatus != StructureUnsupported || result.AuthenticityStatus == AuthenticityInvalid {
		t.Fatal("unknown extension mislabeled as corruption", err)
	}
}
