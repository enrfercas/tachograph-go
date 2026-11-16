package tachograph

import (
	"context"
	"testing"
	"time"

	"github.com/way-platform/tachograph-go/internal/testcard"
)

func TestCardHistoricalTimeDimensionsDoNotPromoteFullVerification(t *testing.T) {
	for _, generation := range []string{"G1", "G2V1", "G2V2"} {
		for _, name := range []string{"noTime", "wrongTimeHash", "incoherentClock", "crossing", "valid", "expired", "expiredInstant", "badRSA", "badECDSA", "missingEF", "missingSignature", "unknownRoot", "oldPolicy", "wrongProofHash"} {
			if generation == "G1" && name == "badECDSA" {
				continue
			}
			t.Run(generation+"/"+name, func(t *testing.T) {
				f, err := testcard.New(generation)
				if err != nil {
					t.Fatal(err)
				}
				tag, cha := 0xc10000, []byte{0xff, 0x54, 0x41, 0x43, 0x48, 0x4f, 1}
				if generation != "G1" {
					tag, cha = 0xc10102, []byte{0xff, 0x53, 0x4d, 0x52, 0x44, 0x54, 0x11}
				}
				if err := f.ReissueCertificate(tag, cha, 1500000000, 1600000000); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "badRSA":
					f.Signatures[0x050100][0] ^= 1
				case "badECDSA":
					f.Signatures[0x050102][0] ^= 1
				case "missingEF":
					delete(f.Files, 0x050300)
					delete(f.Signatures, 0x050300)
				case "missingSignature":
					delete(f.Signatures, 0x050300)
				case "unknownRoot":
					f.RsaRoot.SetKeyId("unknown")
					f.EccRoot.SetCertificateHolderReference("unknown")
				}
				ref := cardTestTime(f)
				ref.Start, ref.End = time.Unix(1550000000, 0).UTC(), time.Unix(1550000060, 0).UTC()
				o := CardInspectionOptions{CertificateResolver: f}
				switch name {
				case "wrongTimeHash":
					ref.SHA256 = "different"
					o.TemporalEvidence = ref
				case "incoherentClock":
					ref.End = ref.Start.Add(-time.Minute)
					o.TemporalEvidence = ref
				case "crossing":
					ref.Start = time.Unix(1599999990, 0).UTC()
					ref.End = time.Unix(1600000010, 0).UTC()
					o.TemporalEvidence = ref
				case "valid":
					o.TemporalEvidence = ref
				case "expired":
					ref.Start = time.Unix(1700000000, 0).UTC()
					ref.End = ref.Start.Add(time.Minute)
					o.TemporalEvidence = ref
				case "expiredInstant":
					ref.Kind, ref.Source = "SIGNATURE_INSTANT", "SYNTHETIC_TEST_REFERENCE"
					ref.Start = time.Unix(1700000000, 0).UTC()
					ref.End = ref.Start
					o.TemporalEvidence = ref
				}
				r := o.Inspect(context.Background(), f.Bytes())
				e := r.AuthenticationEvidence
				if e == nil {
					t.Fatal("missing proof")
				}
				only := name == "noTime" || name == "wrongTimeHash" || name == "incoherentClock" || name == "crossing"
				if name == "oldPolicy" {
					e.PolicyVersion = "card-authentication-2026-11-13/f04-v1"
				}
				if name == "wrongProofHash" {
					e.SHA256 = "other"
				}
				if r.HasOnlyUnevaluatedTime() != only {
					t.Fatalf("onlyTemporal=%v: %+v", r.HasOnlyUnevaluatedTime(), e)
				}
				if only && (e.CryptographicStatus != "VERIFIED" || e.TemporalStatus != "NOT_EVALUATED" || r.AuthenticityStatus != "UNVERIFIED" || r.Rejected()) {
					t.Fatalf("dimensions conflated: %+v", e)
				}
				if (name == "expired" || name == "expiredInstant") && (e.CryptographicStatus != "VERIFIED" || e.TemporalStatus != "INVALID" || !r.Rejected()) {
					t.Fatalf("demonstrated temporal failure lost: %+v", e)
				}
				if name == "valid" && (e.TemporalStatus != "VALID" || r.AuthenticityStatus != "VERIFIED") {
					t.Fatal("full valid result lost")
				}
			})
		}
	}
}
