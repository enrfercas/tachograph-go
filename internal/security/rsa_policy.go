package security

import (
	"encoding/binary"
	"fmt"
	"math/big"

	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// RsaPolicyFields recovers signed policy bytes with the verified issuer key.
// The legacy RSA protobuf has no CHA field; no wire/schema change is needed.
func RsaPolicyFields(cert *securityv1.RsaCertificate, modulus, exponent []byte, issuer string) ([]byte, uint32, error) {
	if err := verifyRsaCertificate(cert, modulus, exponent, issuer); err != nil {
		return nil, 0, err
	}
	recovered := new(big.Int).Exp(new(big.Int).SetBytes(cert.GetRawData()[:128]), new(big.Int).SetBytes(exponent), new(big.Int).SetBytes(modulus)).FillBytes(make([]byte, 128))
	content := recovered[1:107]
	if content[0] != 1 {
		return nil, 0, fmt.Errorf("invalid RSA certificate profile")
	}
	if binary.BigEndian.Uint64(content[1:9]) != binary.BigEndian.Uint64(cert.GetRawData()[186:194]) {
		return nil, 0, fmt.Errorf("signed RSA CAR differs from CAR prime")
	}
	return append([]byte(nil), content[9:16]...), binary.BigEndian.Uint32(content[16:20]), nil
}
