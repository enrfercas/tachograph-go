package tachograph

import (
	"context"
	"crypto/elliptic"
	"testing"

	"github.com/way-platform/tachograph-go/internal/testcard"
)

func TestCompleteCardDownloadWithTestTrust(t *testing.T) {
	for _, generation := range []string{"G1", "G2V1", "G2V2"} {
		t.Run(generation, func(t *testing.T) {
			fixture, err := testcard.New(generation)
			if err != nil {
				t.Fatal(err)
			}
			options := CardDownloadValidationOptions{ExpectedGeneration: generation, CertificateResolver: fixture}
			result, err := options.Validate(context.Background(), fixture.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if result.Contract != "pcsc-card-3/v1" || result.Cryptography != "verified" || !result.StructuralValid || !result.SemanticValid {
				t.Fatal("incomplete validation contract")
			}
			// The normal import parser must accept the same bytes as DRIVER.
			raw, err := Unmarshal(fixture.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(raw)
			if err != nil || parsed.GetDriverCard() == nil {
				t.Fatal("normal import failed", err)
			}
			// A test trust anchor is explicit; it never passes as the real ERCA root.
			if result, err := (CardDownloadValidationOptions{ExpectedGeneration: generation}).Validate(context.Background(), fixture.Bytes()); err != nil || result.AuthenticityStatus != AuthenticityUnverified {
				t.Fatal("test PKI must remain unverified by production trust", err)
			}
			fixture.Signatures[0x050100][0] ^= 1
			if result, err := options.Validate(context.Background(), fixture.Bytes()); err != nil || result.AuthenticityStatus != AuthenticityInvalid {
				t.Fatal("corrupted signature accepted", err)
			}
		})
	}
}

func TestCompleteCardDownloadVerifiesRootLink(t *testing.T) {
	fixture, err := testcard.New("G2V2")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.RotateRoot(); err != nil {
		t.Fatal(err)
	}
	options := CardDownloadValidationOptions{ExpectedGeneration: "G2V2", CertificateResolver: fixture}
	if result, err := options.Validate(context.Background(), fixture.Bytes()); err != nil || result.AuthenticityStatus != AuthenticityVerified {
		t.Fatal(err)
	}
	raw, err := Unmarshal(fixture.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (AuthenticateOptions{CertificateResolver: fixture}).Authenticate(context.Background(), raw); err != nil {
		t.Fatal("normal import authentication failed", err)
	}
	link := fixture.Files[0xc10902]
	link[len(link)-1] ^= 1
	if result, err := options.Validate(context.Background(), fixture.Bytes()); err != nil || result.AuthenticityStatus != AuthenticityInvalid {
		t.Fatal("unverified root link accepted")
	}
	fixture.Files[0xc10902] = make([]byte, 204)
	if result, err := options.Validate(context.Background(), fixture.Bytes()); err != nil || result.AuthenticityStatus != AuthenticityUnverified {
		t.Fatal("unused link cannot establish missing rollover trust")
	}
}

func TestCompleteDownloadMustAlsoBeRecognizedByNormalImport(t *testing.T) {
	for _, generation := range []string{"G1", "G2V1", "G2V2"} {
		t.Run(generation, func(t *testing.T) {
			fixture, err := testcard.New(generation)
			if err != nil {
				t.Fatal(err)
			}
			delete(fixture.Files, 0x000200)
			delete(fixture.Files, 0x000500)
			if result, err := (CardDownloadValidationOptions{ExpectedGeneration: generation, CertificateResolver: fixture}).Validate(context.Background(), fixture.Bytes()); err != nil || !result.SemanticValid || result.AcquisitionStatus != AcquisitionComplete {
				t.Fatal("normal importer must recognize valid application evidence without ICC/IC", err)
			}
			original := fixture.Files[0x050100]
			fixture.Files[0x050100] = append([]byte(nil), original...)
			fixture.Files[0x050100][0] = 2 // WORKSHOP cannot inherit DRIVER layout.
			if _, err := Unmarshal(fixture.Bytes()); err == nil {
				t.Fatal("ambiguous application classified as DRIVER")
			}
			fixture.Files[0x050100] = original
			input := append(fixture.Bytes(), []byte{5, 1, 0, 0, 10}...)
			input = append(input, original...)
			if _, err := Unmarshal(input); err == nil {
				t.Fatal("duplicate application identity accepted without ICC/IC")
			}
		})
	}
}

func TestCompleteG2V2WithP521TestChainAnd132ByteSignatures(t *testing.T) {
	fixture, err := testcard.NewWithCurve("G2V2", elliptic.P521())
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture.Signatures[0x052502]) != 132 {
		t.Fatal("wrong P521 fixture signature length")
	}
	if result, err := (CardDownloadValidationOptions{ExpectedGeneration: "G2V2", CertificateResolver: fixture}).Validate(context.Background(), fixture.Bytes()); err != nil || result.AuthenticityStatus != AuthenticityVerified {
		t.Fatal(err)
	}
}
