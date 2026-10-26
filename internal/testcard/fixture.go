// Package testcard builds anonymous normative-layout test cards. Its generated
// test PKI is never a European trust anchor or evidence of real card operation.
package testcard

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/way-platform/tachograph-go/internal/security"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

type Fixture struct {
	Files      map[int][]byte
	Signatures map[int][]byte
	RsaRoot    *securityv1.RootCertificate
	EccRoot    *securityv1.EccCertificate
	Generation string
	ecKey      *ecdsa.PrivateKey
}

func (f *Fixture) GetRootCertificate(context.Context) (*securityv1.RootCertificate, error) {
	return f.RsaRoot, nil
}
func (f *Fixture) GetEccRootCertificate(context.Context) (*securityv1.EccCertificate, error) {
	return f.EccRoot, nil
}
func (f *Fixture) GetRsaCertificate(context.Context, string) (*securityv1.RsaCertificate, error) {
	return nil, fmt.Errorf("test lookup unavailable")
}
func (f *Fixture) GetEccCertificate(context.Context, string) (*securityv1.EccCertificate, error) {
	return nil, fmt.Errorf("test lookup unavailable")
}

func New(generation string) (*Fixture, error) {
	return NewWithCurve(generation, elliptic.P256())
}

func NewWithCurve(generation string, curve elliptic.Curve) (*Fixture, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	f := &Fixture{Files: map[int][]byte{0x000200: make([]byte, 25), 0x000500: make([]byte, 8)}, Signatures: map[int][]byte{}, Generation: generation}
	f.ecKey = ecKey
	f.RsaRoot = &securityv1.RootCertificate{}
	f.RsaRoot.SetKeyId("1")
	f.RsaRoot.SetRsaModulus(rsaKey.N.Bytes())
	f.RsaRoot.SetRsaExponent(big.NewInt(int64(rsaKey.E)).Bytes())
	root, err := security.UnmarshalEccCertificate(eccCertificate(ecKey, 1, 1))
	if err != nil {
		return nil, err
	}
	f.EccRoot = root
	for _, a := range []int{0, 2} {
		if a == 2 && generation == "G1" {
			break
		}
		activity, vehicles, places, gnss, specific, units, events, faults := 512, 2, 2, 2, 2, 2, 1, 1
		v2 := a == 2 && generation == "G2V2"
		if v2 {
			activity = 13776
			vehicles = 200
			places = 112
			gnss = 336
			specific = 112
			units = 200
			events = 12
			faults = 24
		}
		app := make([]byte, 10)
		if a == 2 {
			app = make([]byte, 17)
			app[1] = 1
		}
		app[0] = 1
		if v2 {
			app[2] = 1
		}
		app[3] = byte(events)
		app[4] = byte(faults)
		binary.BigEndian.PutUint16(app[5:], uint16(activity))
		binary.BigEndian.PutUint16(app[7:], uint16(vehicles))
		if a == 0 {
			app[9] = byte(places)
		} else {
			for _, c := range []struct{ offset, value int }{{9, places}, {11, gnss}, {13, specific}, {15, units}} {
				binary.BigEndian.PutUint16(app[c.offset:], uint16(c.value))
			}
		}
		f.Files[0x050100|a] = app
		eventTypes, vehicleSize, placeSize, placeHeader := 6, 31, 10, 1
		if a == 2 {
			eventTypes = 11
			vehicleSize = 48
			placeSize = 21
			placeHeader = 2
		}
		for _, ef := range []struct{ fid, size int }{{0x0520, 143}, {0x0502, eventTypes * events * 24}, {0x0503, 2 * faults * 24}, {0x0504, 4 + activity}, {0x0505, 2 + vehicles*vehicleSize}, {0x0506, placeHeader + places*placeSize}, {0x0508, 46}, {0x0522, 280}} {
			f.Files[ef.fid<<8|a] = make([]byte, ef.size)
		}
		if a == 0 {
			f.Files[0xc10000] = rsaCertificate(rsaKey, 1, 3)
			f.Files[0xc10800] = rsaCertificate(rsaKey, 1, 1)
		} else {
			f.Files[0xc10102] = eccCertificate(ecKey, 2, 3)
			f.Files[0xc10802] = eccCertificate(ecKey, 1, 2)
			f.Files[0xc10902] = eccCertificate(ecKey, 1, 1)
			f.Files[0x052202] = make([]byte, 2+specific*5)
			f.Files[0x052302] = make([]byte, 2+units*10)
			f.Files[0x052402] = make([]byte, 2+gnss*18)
			if v2 {
				f.Files[0x052502] = []byte{0, 8, 4, 96, 6, 88, 1, 80, 12, 0}
				for _, ef := range []struct{ fid, size int }{{0x0526, 2 + places*5}, {0x0527, 2 + gnss*5}, {0x0528, 2 + 1120*17}, {0x0529, 2 + 1624*20}, {0x0530, 2 + 336*5}, {0x0540, 3072}} {
					f.Files[ef.fid<<8|2] = make([]byte, ef.size)
				}
			}
		}
	}
	for tag, data := range f.Files {
		if tag>>8 < 0x100 || tag>>8 >= 0xc000 {
			continue
		}
		if tag&2 == 0 {
			h := sha1.Sum(data)
			signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA1, h[:])
			if err != nil {
				return nil, err
			}
			f.Signatures[tag] = signature
		} else {
			h := eccHash(ecKey, data)
			r, s, err := ecdsa.Sign(rand.Reader, ecKey, h)
			if err != nil {
				return nil, err
			}
			width := (ecKey.Params().BitSize + 7) / 8
			f.Signatures[tag] = append(r.FillBytes(make([]byte, width)), s.FillBytes(make([]byte, width))...)
		}
	}
	return f, nil
}

func rsaCertificate(key *rsa.PrivateKey, car, chr uint64) []byte {
	c := make([]byte, 164)
	c[0] = 1
	binary.BigEndian.PutUint64(c[1:], car)
	binary.BigEndian.PutUint32(c[16:], 0xffffffff)
	binary.BigEndian.PutUint64(c[20:], chr)
	key.N.FillBytes(c[28:156])
	binary.BigEndian.PutUint64(c[156:], uint64(key.E))
	h := sha1.Sum(c)
	recovered := append([]byte{0x6a}, c[:106]...)
	recovered = append(recovered, h[:]...)
	recovered = append(recovered, 0xbc)
	signature := new(big.Int).Exp(new(big.Int).SetBytes(recovered), key.D, key.N).FillBytes(make([]byte, 128))
	result := append(signature, c[106:]...)
	return binary.BigEndian.AppendUint64(result, car)
}

func eccCertificate(key *ecdsa.PrivateKey, car, chr uint64) []byte {
	return eccCertificateForKey(&key.PublicKey, key, car, chr)
}

func eccCertificateForKey(publicKey *ecdsa.PublicKey, signer *ecdsa.PrivateKey, car, chr uint64) []byte {
	wrap := func(class, tag int, compound bool, b []byte) []byte {
		out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: b})
		if err != nil {
			panic(err)
		}
		return out
	}
	field := func(tag int, b []byte) []byte { return wrap(asn1.ClassApplication, tag, false, b) }
	body := field(41, []byte{0})
	body = append(body, field(2, binary.BigEndian.AppendUint64(nil, car))...)
	body = append(body, field(76, make([]byte, 7))...)
	curveOID := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	switch publicKey.Params().BitSize {
	case 384:
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case 521:
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	}
	oid, _ := asn1.Marshal(curveOID)
	pk := append(oid, wrap(asn1.ClassContextSpecific, 6, false, elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y))...)
	body = append(body, wrap(asn1.ClassApplication, 73, true, pk)...)
	body = append(body, field(32, binary.BigEndian.AppendUint64(nil, chr))...)
	body = append(body, field(37, []byte{0, 0, 0, 1})...)
	body = append(body, field(36, []byte{0xff, 0xff, 0xff, 0xff})...)
	body = wrap(asn1.ClassApplication, 78, true, body)
	h := eccHash(signer, body)
	r, s, err := ecdsa.Sign(rand.Reader, signer, h)
	if err != nil {
		panic(err)
	}
	width := (signer.Params().BitSize + 7) / 8
	sig := append(r.FillBytes(make([]byte, width)), s.FillBytes(make([]byte, width))...)
	return wrap(asn1.ClassApplication, 33, true, append(body, field(55, sig)...))
}

func eccHash(key *ecdsa.PrivateKey, data []byte) []byte {
	switch key.Params().BitSize {
	case 256:
		h := sha256.Sum256(data)
		return h[:]
	case 384:
		h := sha512.Sum384(data)
		return h[:]
	default:
		h := sha512.Sum512(data)
		return h[:]
	}
}

// RotateRoot exercises C109 with a distinct test key; the original test trust
// anchor stays unchanged. It cannot introduce trust into the production resolver.
func (f *Fixture) RotateRoot() error {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	f.Files[0xc10902] = eccCertificateForKey(&newKey.PublicKey, f.ecKey, 1, 4)
	f.Files[0xc10802] = eccCertificateForKey(&f.ecKey.PublicKey, newKey, 4, 2)
	return nil
}

func (f *Fixture) Bytes() []byte {
	var out []byte
	appendBlock := func(tag int, b []byte) {
		out = append(out, byte(tag>>16), byte(tag>>8), byte(tag))
		out = binary.BigEndian.AppendUint16(out, uint16(len(b)))
		out = append(out, b...)
	}
	// Stable order, with each original signature adjacent to its own application.
	for _, a := range []int{0, 2} {
		for _, fid := range []int{2, 5, 0xc100, 0xc101, 0xc108, 0xc109, 0x0501, 0x0520, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0508, 0x050e, 0x0522, 0x0523, 0x0524, 0x0525, 0x0526, 0x0527, 0x0528, 0x0529, 0x0530, 0x0540} {
			tag := fid<<8 | a
			if b, ok := f.Files[tag]; ok {
				appendBlock(tag, b)
				if sig, ok := f.Signatures[tag]; ok {
					appendBlock(tag+1, sig)
				}
			}
		}
	}
	return out
}
