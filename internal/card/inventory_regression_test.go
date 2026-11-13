package card

import (
	"context"
	"testing"

	"github.com/way-platform/tachograph-go/internal/testcard"
)

func TestF01MissingDataAndSignatureMustNotAuthenticate(t *testing.T) {
	for _, generation := range []string{"G1", "G2V1", "G2V2"} {
		t.Run(generation, func(t *testing.T) {
			f, err := testcard.New(generation)
			if err != nil {
				t.Fatal(err)
			}
			tag := 0x050300
			if generation != "G1" {
				tag = 0x050302
			}
			delete(f.Files, tag)
			delete(f.Signatures, tag)
			raw, err := (UnmarshalOptions{}).UnmarshalRawCardFile(f.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			err = (AuthenticateOptions{CertificateResolver: f}).AuthenticateRawCardFile(context.Background(), raw)
			t.Logf("F01 generation=%s removed=%06x/%06x authenticationError=%v", generation, tag, tag+1, err)
			if err == nil {
				t.Error("F01: incomplete inventory authenticated")
			}
		})
	}
}
