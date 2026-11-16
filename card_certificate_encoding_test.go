package tachograph

import (
	"context"
	"fmt"
	"testing"

	"github.com/way-platform/tachograph-go/internal/testcard"
)

func TestCardPolicyRejectsMalformedCertificateWrapperOnRawAuthentication(t *testing.T) {
	for _, gen := range []string{"G2V1", "G2V2"} {
		for _, tag := range []int{0xc10102, 0xc10802, 0xc10902} {
			t.Run(fmt.Sprintf("%s/%06X", gen, tag), func(t *testing.T) {
				f, err := testcard.New(gen)
				if err != nil {
					t.Fatal(err)
				}
				if tag == 0xc10902 {
					if err := f.RotateRoot(); err != nil {
						t.Fatal(err)
					}
				}
				// Change only the unsigned CVC wrapper tag. The signed body and
				// mathematical signature are intact; it is not a 7F21 certificate.
				f.Files[tag][1] = 0x20
				raw, err := Unmarshal(f.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := (AuthenticateOptions{CertificateResolver: f, TemporalEvidence: cardTestTime(f)}).Authenticate(context.Background(), raw); err == nil {
					t.Fatal("malformed certificate wrapper produced VERIFIED")
				}
			})
		}
	}
}
