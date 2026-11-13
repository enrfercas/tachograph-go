package card

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
)

// ValidateCompleteDownload is deliberately separate from historical parsing.
// Appendix 2 TCS_153/155 and Appendix 7 DDP_035 define this DRIVER profile.
// expected is the generation observed on the physical card, not inferred from
// a potentially legacy-only DDD (MIG_012). Unknown versions/EFs fail closed.
func ValidateCompleteDownload(raw *cardv1.RawCardFile, expected string) error {
	return validateDownloadStructure(raw, expected, true, false)
}

func validateDownloadStructure(raw *cardv1.RawCardFile, expected string, requireLink, historical bool) error {
	if expected != "G1" && expected != "G2V1" && expected != "G2V2" {
		return &DownloadStructureError{Unsupported: true, Reason: "generation_unsupported"}
	}
	files := make(map[int][]byte)
	previous := -1
	for _, record := range raw.GetRecords() {
		tag := int(record.GetTag())
		appendix, fid := tag&255, tag>>8
		if appendix > 3 || len(record.GetValue()) == 0 || len(record.GetValue()) >= 65535 {
			return fmt.Errorf("invalid TLV %06x", tag)
		}
		if _, found := files[tag]; found {
			return fmt.Errorf("duplicate TLV %06x", tag)
		}
		if appendix&1 != 0 && previous != tag-1 {
			return fmt.Errorf("signature without same-application EF %06x", tag)
		}
		if _, ok := mapFidToElementaryFileType(uint16(fid), record.GetGeneration()); !ok {
			return &DownloadStructureError{Unsupported: true, Reason: "unknown_ef", Tag: tag}
		}
		files[tag] = record.GetValue()
		previous = tag
	}
	if expected == "G2V2" && files[0x050100] != nil && files[0x050102] == nil {
		return fmt.Errorf("G2V2 legacy G1 application only; direct download incomplete")
	}
	require := func(fid, appendix int) ([]byte, error) {
		b, ok := files[fid<<8|appendix]
		if !ok {
			return nil, fmt.Errorf("required EF %04x/%02x missing", fid, appendix)
		}
		return b, nil
	}
	size := func(fid, appendix, length int) error {
		b := files[fid<<8|appendix]
		if b != nil && len(b) != length {
			return fmt.Errorf("EF %04x/%02x length %d, expected %d", fid, appendix, len(b), length)
		}
		return nil
	}
	for _, common := range []struct{ fid, length int }{{2, 25}, {5, 8}} {
		// DDP_035 permits these MF files to be absent.
		if err := size(common.fid, 0, common.length); err != nil {
			return err
		}
		if other := files[common.fid<<8|2]; other != nil {
			// Historical exporters repeat identical MF bytes with a G2 appendix.
			// Retain the original tags; never treat divergent copies as equivalent.
			if !bytes.Equal(other, files[common.fid<<8]) {
				return fmt.Errorf("conflicting MF copies")
			}
		}
	}
	for _, appendix := range []int{0, 2} {
		if appendix == 2 && expected == "G1" {
			for tag := range files {
				if tag&2 != 0 {
					return fmt.Errorf("G2 data inconsistent with observed G1 card")
				}
			}
			break
		}
		app, err := require(0x0501, appendix)
		if err != nil {
			return err
		}
		want := 10
		if appendix == 2 {
			want = 17
		}
		if len(app) != want || app[0] != 1 {
			return fmt.Errorf("invalid DRIVER Application_Identification")
		}
		if appendix == 2 {
			version := byte(0)
			if expected == "G2V2" {
				version = 1
			}
			if app[1] != 1 || app[2] != version {
				return &DownloadStructureError{Unsupported: true, Reason: "application_version_unsupported"}
			}
		} else if app[1] != 0 || app[2] != 0 {
			return fmt.Errorf("unknown G1 cardStructureVersion")
		}
		required := RequiredDownloadData(appendix)
		certs := RequiredDownloadCertificates(appendix, requireLink)
		for _, fid := range append(required, certs...) {
			if _, err := require(fid, appendix); err != nil {
				return err
			}
		}
		for tag := range files {
			if tag&255 != appendix {
				continue
			}
			fid := tag >> 8
			allowed := fid == 2 || fid == 5 || fid == 0x0507 || fid == 0x0521
			if historical && (fid == 0x050e || appendix == 2 && fid == 0xc109) {
				continue
			}
			for _, f := range append(append([]int(nil), required...), certs...) {
				allowed = allowed || fid == f
			}
			if appendix == 2 && fid == 0xc100 {
				allowed = true
			}
			if appendix == 2 && (fid >= 0x0525 && fid <= 0x0529 || fid == 0x0530 || fid == 0x0540) {
				allowed = true
			}
			if !allowed {
				return &DownloadStructureError{Unsupported: true, Reason: "ef_outside_acquisition_profile", Tag: tag}
			}
			if fid == 2 || fid == 5 || fid >= 0xc000 {
				if files[tag+1] != nil {
					return fmt.Errorf("unexpected signature for unsigned EF %06x", tag)
				}
				if appendix == 2 && fid >= 0xc000 {
					if fid == 0xc109 && len(files[tag]) >= 204 && len(files[tag]) <= 341 && bytes.Equal(files[tag], make([]byte, len(files[tag]))) {
						continue
					}
					if err := validateDownloadEccCertificate(files[tag]); err != nil {
						return fmt.Errorf("EF %04x: %w", fid, err)
					}
				}
				continue
			}
			sig := files[tag+1]
			if sig == nil {
				return &DownloadStructureError{Reason: "required_signature_missing", Tag: tag}
			}
			validLength := len(sig) == 128
			if appendix == 2 {
				validLength = len(sig) == 64 || len(sig) == 96 || len(sig) == 128 || len(sig) == 132
			}
			if !validLength {
				return fmt.Errorf("missing or incomplete signature %06x", tag)
			}
		}
		u16 := func(i int) int { return int(binary.BigEndian.Uint16(app[i:])) }
		places, gnss, specific, units := int(app[9]), 0, 56, 0
		eventTypes, vehicleSize, placeSize, placeHeader := 6, 31, 10, 1
		if appendix == 2 {
			places = u16(9)
			gnss = u16(11)
			specific = u16(13)
			units = u16(15)
			eventTypes = 11
			vehicleSize = 48
			placeSize = 21
			placeHeader = 2
		}
		checks := []struct{ fid, length int }{
			{0x0520, 143}, {0x0521, 53}, {0x0502, eventTypes * int(app[3]) * 24}, {0x0503, 2 * int(app[4]) * 24},
			{0x0504, 4 + u16(5)}, {0x0505, 2 + u16(7)*vehicleSize}, {0x0506, placeHeader + places*placeSize},
			{0x0507, 19}, {0x0508, 46}, {0x0522, specific * 5},
		}
		if appendix == 2 {
			checks[len(checks)-1].length += 2
			checks = append(checks, struct{ fid, length int }{0x0523, 2 + units*10}, struct{ fid, length int }{0x0524, 2 + gnss*18})
		}
		for _, check := range checks {
			if err := size(check.fid, appendix, check.length); err != nil {
				return err
			}
		}
		for _, ring := range []struct{ fid, count, header int }{{0x0505, u16(7), 2}, {0x0506, places, placeHeader}, {0x0522, specific, 2}, {0x0523, units, 2}, {0x0524, gnss, 2}} {
			if appendix == 0 && ring.fid >= 0x0522 {
				continue
			}
			if err := validateDownloadPointer(files[ring.fid<<8|appendix], ring.count, ring.header); err != nil {
				return fmt.Errorf("EF %04x: %w", ring.fid, err)
			}
		}
		if err := validateCompleteActivity(files[0x0504<<8|appendix]); err != nil {
			return err
		}
		if appendix == 0 {
			for _, fid := range certs {
				if err := size(fid, 0, 194); err != nil {
					return err
				}
			}
		} else {
			v2 := files[0x052502]
			border, load, types, config := 0, 0, 0, 0
			if v2 != nil {
				if len(v2) > 10 && int(binary.BigEndian.Uint16(v2)) == len(v2)-2 {
					return &DownloadStructureError{Unsupported: true, Reason: "application_v2_extension_unsupported", Tag: 0x052502}
				}
				decoded, err := (UnmarshalOptions{}).unmarshalApplicationIdentificationV2(v2, cardv1.CardType_DRIVER_CARD)
				if err != nil {
					return err
				}
				caps := decoded.GetDriver()
				border = int(caps.GetBorderCrossingRecordsCount())
				load = int(caps.GetLoadUnloadRecordsCount())
				types = int(caps.GetLoadTypeEntryRecordsCount())
				config = int(caps.GetVuConfigurationLengthRange())
			}
			// TCS_155 fixes these capacities for released DRIVER G2V2 cards.
			if expected == "G2V2" {
				if app[3] != 12 || app[4] != 24 || u16(5) != 13776 || u16(7) != 200 || places != 112 || gnss != 336 || specific != 112 || units != 200 || (v2 != nil && !bytes.Equal(v2, []byte{0, 8, 4, 96, 6, 88, 1, 80, 12, 0})) {
					return &DownloadStructureError{Unsupported: true, Reason: "unknown_driver_capacities"}
				}
				// Validation limits from TCS_155, not fabricated semantic fields.
				border, load, types, config = 1120, 1624, 336, 3072
			}
			for _, ring := range []struct{ fid, count, record int }{{0x0526, places, 5}, {0x0527, gnss, 5}, {0x0528, border, 17}, {0x0529, load, 20}, {0x0530, types, 5}} {
				data := files[ring.fid<<8|2]
				if data == nil {
					continue
				}
				if ring.count == 0 {
					if _, _, err := cyclicRecords(data, ring.record); err != nil {
						return err
					}
					continue
				}
				if err := size(ring.fid, 2, 2+ring.count*ring.record); err != nil {
					return err
				}
				if err := validateDownloadPointer(files[ring.fid<<8|2], ring.count, 2); err != nil {
					return fmt.Errorf("EF %04x: %w", ring.fid, err)
				}
			}
			if files[0x054002] != nil && config == 0 {
				return &DownloadStructureError{Unsupported: true, Reason: "configuration_capacity_unknown", Tag: 0x054002}
			}
			if err := size(0x0540, 2, config); err != nil {
				return err
			}
		}
	}
	return nil
}

// DownloadStructureError distinguishes unsupported extensions from corruption.
// A missing signature is acquisition incompleteness, not proof of forgery.
type DownloadStructureError struct {
	Unsupported bool
	Reason      string
	Tag         int
}

func (e *DownloadStructureError) Error() string { return fmt.Sprintf("%s (tag %06x)", e.Reason, e.Tag) }

// Reject trailing/incomplete certificate elements even though historical
// security decoding accepts some tails. Appendix 11 CVC application tags.
func validateDownloadEccCertificate(b []byte) error {
	if len(b) < 204 || len(b) > 341 {
		return fmt.Errorf("incomplete ECC certificate")
	}
	read := func(input []byte, tag int, compound bool) (asn1.RawValue, []byte, error) {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(input, &v)
		if err != nil || v.Class != asn1.ClassApplication || v.Tag != tag || v.IsCompound != compound {
			return v, nil, fmt.Errorf("invalid CVC element %d", tag)
		}
		return v, rest, nil
	}
	outer, rest, err := read(b, 33, true)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected certificate tail")
	}
	body, rest, err := read(outer.Bytes, 78, true)
	if err != nil {
		return err
	}
	sig, rest, err := read(rest, 55, false)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected certificate elements")
	}
	if n := len(sig.Bytes); n != 64 && n != 96 && n != 128 && n != 132 {
		return fmt.Errorf("incomplete certificate signature")
	}
	content := body.Bytes
	for _, field := range []struct {
		tag, length int
		compound    bool
	}{{41, 1, false}, {2, 8, false}, {76, 7, false}, {73, -1, true}, {32, 8, false}, {37, 4, false}, {36, 4, false}} {
		v, next, err := read(content, field.tag, field.compound)
		if err != nil {
			return err
		}
		if field.length >= 0 && len(v.Bytes) != field.length {
			return fmt.Errorf("invalid certificate field length")
		}
		if field.tag == 41 && v.Bytes[0] != 0 {
			return &DownloadStructureError{Unsupported: true, Reason: "certificate_profile_unsupported"}
		}
		if field.tag == 73 {
			var oid asn1.ObjectIdentifier
			key, err := asn1.Unmarshal(v.Bytes, &oid)
			if err != nil {
				return fmt.Errorf("invalid key OID")
			}
			var point asn1.RawValue
			tail, err := asn1.Unmarshal(key, &point)
			if err != nil || len(tail) != 0 || point.Class != asn1.ClassContextSpecific || point.Tag != 6 || len(point.Bytes) < 2 || point.Bytes[0] != 4 {
				return fmt.Errorf("incomplete certificate public point")
			}
		}
		content = next
	}
	if len(content) != 0 {
		return fmt.Errorf("unexpected certificate body tail")
	}
	return nil
}

func validateDownloadPointer(b []byte, count, header int) error {
	if b == nil {
		return nil
	}
	if len(b) < header {
		return fmt.Errorf("truncated pointer")
	}
	index := int(b[0])
	if header == 2 {
		index = int(binary.BigEndian.Uint16(b))
	}
	if count <= 0 || index >= count {
		return fmt.Errorf("pointer %d outside capacity %d", index, count)
	}
	return nil
}

// Verify the linked cyclic activity records without changing their interpretation.
// Historical parsing deliberately tolerates malformed/partially stored records.
func validateCompleteActivity(b []byte) error {
	if len(b) < 5 {
		return fmt.Errorf("truncated activity EF")
	}
	buffer := b[4:]
	oldest, newest := int(binary.BigEndian.Uint16(b)), int(binary.BigEndian.Uint16(b[2:]))
	if oldest >= len(buffer) || newest >= len(buffer) {
		return fmt.Errorf("activity pointer outside buffer")
	}
	if bytes.Equal(buffer, make([]byte, len(buffer))) && oldest == 0 && newest == 0 {
		return nil
	}
	read16 := func(pos int) int { return int(buffer[pos%len(buffer)])<<8 | int(buffer[(pos+1)%len(buffer)]) }
	seen := map[int]bool{}
	pos := newest
	used := 0
	for {
		if seen[pos] {
			return fmt.Errorf("activity ring does not reach oldest record")
		}
		seen[pos] = true
		length := read16(pos + 2)
		used += length
		if length < 12 || length > len(buffer) || length%2 != 0 || used > len(buffer) {
			return fmt.Errorf("incomplete activity daily record")
		}
		if pos == oldest {
			break
		}
		previous := read16(pos)
		if previous < 12 || previous > len(buffer) || previous%2 != 0 {
			return fmt.Errorf("invalid activity previous length")
		}
		next := (pos - previous + len(buffer)) % len(buffer)
		if read16(next+2) != previous {
			return fmt.Errorf("inconsistent activity linked lengths")
		}
		pos = next
	}
	return nil
}
