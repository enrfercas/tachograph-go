package tachograph

import (
	"context"
	"fmt"
	"testing"

	"github.com/way-platform/tachograph-go/internal/testcard"
)

func TestCardInventoryEveryRequiredPairAndSignature(t *testing.T) {
	// Independent normative expectations, not an enumeration of emitted rows.
	minimum := []int{0x0501, 0x0520, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0508, 0x0522}
	for _, generation := range []string{"G1", "G2V1", "G2V2"} {
		f, err := testcard.New(generation)
		if err != nil {
			t.Fatal(err)
		}
		o := CardInspectionOptions{ExpectedGeneration: generation, ObservedCard: true, CertificateResolver: f}
		if r := o.Inspect(context.Background(), f.Bytes()); r.AcceptanceStatus != "VALID" {
			t.Fatalf("%s: %+v", generation, r.Defects)
		}
		for _, app := range []int{0, 2} {
			if app == 2 && generation == "G1" {
				break
			}
			ids := append([]int(nil), minimum...)
			if app == 2 {
				ids = append(ids, 0x0523, 0x0524)
			}
			for _, fid := range ids {
				tag := fid<<8 | app
				for _, pair := range []bool{true, false} {
					t.Run(fmt.Sprintf("%s/%06x/pair=%v", generation, tag, pair), func(t *testing.T) {
						data, signature := f.Files[tag], f.Signatures[tag]
						if pair {
							delete(f.Files, tag)
						}
						delete(f.Signatures, tag)
						defer func() { f.Files[tag] = data; f.Signatures[tag] = signature }()
						r := o.Inspect(context.Background(), f.Bytes())
						want := "INVALID_MISSING_REQUIRED_SIGNATURE"
						if pair {
							want = "INVALID_MISSING_REQUIRED_EF"
						}
						if r.AcceptanceStatus != want {
							t.Fatalf("%s: %+v", r.AcceptanceStatus, r.Defects)
						}
						found := false
						for _, d := range r.Defects {
							found = found || d.Tag == tag && d.Scope == "inventory"
						}
						if !found {
							t.Fatal("EF identity lost")
						}
					})
				}
			}
		}
	}
}

func TestCardInspectionExceptionsTrustAndMalformed(t *testing.T) {
	for _, name := range []string{"conditionalAbsent", "observedConditionalMissing", "g1Compatible", "zeroLink", "missingTrust", "missingSignatureAndTrust", "missingCertificate", "undeterminedProfile", "invalidSignature", "truncated", "duplicate", "multipleDefects"} {
		t.Run(name, func(t *testing.T) {
			f, err := testcard.New("G2V2")
			if err != nil {
				t.Fatal(err)
			}
			o := CardInspectionOptions{CertificateResolver: f}
			want := "VALID"
			input := []byte(nil)
			switch name {
			case "conditionalAbsent", "observedConditionalMissing":
				for _, fid := range []int{0x0525, 0x0526, 0x0527, 0x0528, 0x0529, 0x0530, 0x0540} {
					delete(f.Files, fid<<8|2)
					delete(f.Signatures, fid<<8|2)
				}
				if name == "observedConditionalMissing" {
					o.ObservedPresentTags = []int{0x052802}
					want = "INVALID_MISSING_REQUIRED_EF"
				}
			case "g1Compatible":
				for tag := range f.Files {
					if tag&2 != 0 {
						delete(f.Files, tag)
						delete(f.Signatures, tag)
					}
				}
			case "zeroLink":
				f.Files[0xc10902] = make([]byte, 204)
			case "missingTrust":
				o.CertificateResolver = nil
				want = "UNVERIFIED"
			case "missingSignatureAndTrust":
				o.CertificateResolver = nil
				delete(f.Signatures, 0x050302)
				want = "INVALID_MISSING_REQUIRED_SIGNATURE"
			case "missingCertificate":
				delete(f.Files, 0xc10102)
				want = "INVALID_MISSING_REQUIRED_EF"
			case "undeterminedProfile":
				delete(f.Files, 0x050100)
				delete(f.Signatures, 0x050100)
				delete(f.Files, 0x050102)
				delete(f.Signatures, 0x050102)
				want = "PROFILE_UNDETERMINED"
			case "invalidSignature":
				f.Signatures[0x050302][0] ^= 1
				want = "INVALID_SIGNATURE"
			case "truncated":
				input = f.Bytes()
				input = input[:len(input)-1]
				want = "INVALID_STRUCTURE"
			case "duplicate":
				input = f.Bytes()
				input = append(input, input[:30]...)
				want = "INVALID_STRUCTURE"
			case "multipleDefects":
				delete(f.Files, 0x050302)
				delete(f.Signatures, 0x050302)
				delete(f.Signatures, 0x050402)
				want = "INVALID_MISSING_REQUIRED_EF"
			}
			if input == nil {
				input = f.Bytes()
			}
			r := o.Inspect(context.Background(), input)
			if r.AcceptanceStatus != want {
				t.Fatalf("%s want %s: %+v", r.AcceptanceStatus, want, r.Defects)
			}
			if name == "multipleDefects" && len(r.Defects) < 2 {
				t.Fatal("only first defect retained")
			}
			if name == "truncated" && r.StoppedOffset == nil {
				t.Fatal("truncation offset missing")
			}
			if name == "invalidSignature" {
				found := false
				for _, b := range r.Blocks {
					if b.Tag == 0x050302 && b.CryptographicStatus == "DATA_SIGNATURE_INVALID" {
						found = true
					}
				}
				if !found {
					t.Fatal("invalid signature lost its EF identity")
				}
			}
		})
	}
	for _, b := range [][]byte{nil, {0}, {0, 2}, {0, 2, 0, 0}, {0, 2, 0, 0, 25, 1}} {
		r := (CardInspectionOptions{}).Inspect(context.Background(), b)
		if r.AcceptanceStatus != "INVALID_STRUCTURE" {
			t.Fatal("truncated data approved")
		}
	}
}

func TestCardInspectionHistoricalExceptions(t *testing.T) {
	for _, name := range []string{"historicalG2V1WithoutLink", "observedG2V1RequiresLink", "historicalLastDownload", "optionalMFAbsent", "identicalMFCopies"} {
		t.Run(name, func(t *testing.T) {
			generation := "G2V1"
			if name == "historicalLastDownload" {
				generation = "G1"
			}
			f, err := testcard.New(generation)
			if err != nil {
				t.Fatal(err)
			}
			o := CardInspectionOptions{CertificateResolver: f}
			want := "VALID"
			switch name {
			case "historicalG2V1WithoutLink", "observedG2V1RequiresLink":
				delete(f.Files, 0xc10902)
				if name == "observedG2V1RequiresLink" {
					o.ObservedCard = true
					o.ExpectedGeneration = generation
					want = "INVALID_MISSING_REQUIRED_EF"
				}
			case "historicalLastDownload":
				f.Files[0x050e00] = []byte{0x65, 0x53, 0xf1, 0}
			case "optionalMFAbsent":
				delete(f.Files, 0x000200)
				delete(f.Files, 0x000500)
			case "identicalMFCopies":
				f.Files[0x000202] = append([]byte(nil), f.Files[0x000200]...)
				f.Files[0x000502] = append([]byte(nil), f.Files[0x000500]...)
			}
			r := o.Inspect(context.Background(), f.Bytes())
			if r.AcceptanceStatus != want {
				t.Fatalf("%s want %s: %+v", r.AcceptanceStatus, want, r.Defects)
			}
		})
	}
}
