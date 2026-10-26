package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

func TestCardEccSignatureUsesCurveWidth(t *testing.T) {
	for _, test := range []struct {
		name, oid string
		curve     elliptic.Curve
	}{{"P256", "1.2.840.10045.3.1.7", elliptic.P256()}, {"P384", "1.3.132.0.34", elliptic.P384()}, {"P521", "1.3.132.0.35", elliptic.P521()}} {
		t.Run(test.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(test.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("anonymous G2V2 EF test")
			var hash []byte
			switch test.curve.Params().BitSize {
			case 256:
				h := sha256.Sum256(data)
				hash = h[:]
			case 384:
				h := sha512.Sum384(data)
				hash = h[:]
			case 521:
				h := sha512.Sum512(data)
				hash = h[:]
			}
			r, s, err := ecdsa.Sign(rand.Reader, key, hash)
			if err != nil {
				t.Fatal(err)
			}
			width := (test.curve.Params().BitSize + 7) / 8
			signature := append(r.FillBytes(make([]byte, width)), s.FillBytes(make([]byte, width))...)
			cert := &securityv1.EccCertificate{}
			pk := &securityv1.EccCertificate_PublicKey{}
			pk.SetDomainParametersOid(test.oid)
			pk.SetPublicPointX(key.X.FillBytes(make([]byte, width)))
			pk.SetPublicPointY(key.Y.FillBytes(make([]byte, width)))
			cert.SetPublicKey(pk)
			if err := VerifyEccDataSignature(data, signature, cert); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range [][]byte{signature[:len(signature)-1], append(append([]byte(nil), signature...), 0), make([]byte, len(signature))} {
				if err := VerifyEccDataSignature(data, invalid, cert); err == nil {
					t.Fatal("invalid or truncated signature accepted")
				}
			}
			if err := VerifyEccDataSignature(append(data, 0), signature, cert); err == nil {
				t.Fatal("altered EF accepted")
			}
		})
	}
}
