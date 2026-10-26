package card

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/way-platform/tachograph-go/internal/testcard"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	"google.golang.org/protobuf/proto"
)

func completeTestCard(t *testing.T) *cardv1.RawCardFile {
	t.Helper()
	fixture, err := testcard.New("G2V2")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := (UnmarshalOptions{}).UnmarshalRawCardFile(fixture.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCompleteDownloadRejectsMissingTruncatedAdditionalEFs(t *testing.T) {
	raw := completeTestCard(t)
	if err := ValidateCompleteDownload(raw, "G2V2"); err != nil {
		t.Fatal(err)
	}
	for i, record := range raw.GetRecords() {
		tag := record.GetTag()
		for _, mutation := range []string{"truncated", "extra", "absent"} {
			t.Run(fmt.Sprintf("%06x/%s", tag, mutation), func(t *testing.T) {
				copy := proto.Clone(raw).(*cardv1.RawCardFile)
				r := copy.GetRecords()[i]
				switch mutation {
				case "truncated":
					r.SetValue(r.GetValue()[:len(r.GetValue())-1])
				case "extra":
					r.SetValue(append(r.GetValue(), 0))
				case "absent":
					records := copy.GetRecords()
					copy.SetRecords(append(records[:i], records[i+1:]...))
				}
				err := ValidateCompleteDownload(copy, "G2V2")
				optionalCommon := tag == 0x000200 || tag == 0x000500
				if optionalCommon && mutation == "absent" {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				if err == nil {
					t.Fatal("accepted incomplete/extra EF or signature")
				}
			})
		}
	}
}

func TestCompleteDownloadRejectsWrongApplicationDuplicatesAndPointers(t *testing.T) {
	raw := completeTestCard(t)
	for _, mutation := range []string{"duplicate", "reservedAppendix", "legacyOnly", "unknownVersion", "unknownEF", "ringPointer", "activityPointer", "activityRecord"} {
		t.Run(mutation, func(t *testing.T) {
			copy := proto.Clone(raw).(*cardv1.RawCardFile)
			switch mutation {
			case "duplicate":
				copy.SetRecords(append(copy.GetRecords(), copy.GetRecords()[0]))
			case "reservedAppendix":
				copy.GetRecords()[0].SetTag(0x000204)
			case "legacyOnly":
				var records []*cardv1.RawCardFile_Record
				for _, r := range copy.GetRecords() {
					if r.GetTag()&2 == 0 {
						records = append(records, r)
					}
				}
				copy.SetRecords(records)
			case "unknownEF":
				copy.GetRecords()[0].SetTag(0x999900)
			default:
				for _, r := range copy.GetRecords() {
					switch {
					case mutation == "unknownVersion" && r.GetTag() == 0x050102:
						r.GetValue()[2] = 2
					case mutation == "ringPointer" && r.GetTag() == 0x052802:
						binary.BigEndian.PutUint16(r.GetValue(), 1120)
					case mutation == "activityPointer" && r.GetTag() == 0x050402:
						binary.BigEndian.PutUint16(r.GetValue(), 13776)
					case mutation == "activityRecord" && r.GetTag() == 0x050402:
						r.GetValue()[7] = 13
					}
				}
			}
			if err := ValidateCompleteDownload(copy, "G2V2"); err == nil {
				t.Fatal("accepted", mutation)
			}
		})
	}
}

func TestG2V2SemanticRecordsAndOriginalProvenance(t *testing.T) {
	raw := completeTestCard(t)
	for _, r := range raw.GetRecords() {
		if r.GetTag() == 0x052802 {
			binary.BigEndian.PutUint16(r.GetValue(), 1000)
		}
		if r.GetTag() == 0x053002 {
			binary.BigEndian.PutUint16(r.GetValue(), 335)
			r.GetValue()[6] = 0xfe
		}
	}
	if err := ValidateCompleteDownload(raw, "G2V2"); err != nil {
		t.Fatal(err)
	}
	parsed, err := (ParseOptions{PreserveRawData: true}).ParseRawDriverCardFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	g2 := parsed.GetTachographG2()
	if len(g2.GetBorderCrossings().GetRecords()) != 1120 || g2.GetBorderCrossings().GetNewestRecordIndex() != 1000 || len(g2.GetLoadUnloadOperations().GetRecords()) != 1624 || len(g2.GetLoadTypeEntries().GetRecords()) != 336 || len(g2.GetPlacesAuthentication().GetRecords()) != 112 || len(g2.GetGnssPlacesAuthentication().GetRecords()) != 336 || len(g2.GetVuConfiguration().GetRawData()) != 3072 {
		t.Fatal("lost semantic records/capacities")
	}
	if g2.GetLoadTypeEntries().GetRecords()[0].HasLoadTypeEntered() {
		t.Fatal("invented unknown enum")
	}
	original, err := (MarshalOptions{}).MarshalRawCardFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := (UnmarshalOptions{}).UnmarshalRawCardFile(original)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(raw, decoded) {
		t.Fatal("lost raw values, tags, signatures or application")
	}
	if _, err := (MarshalOptions{}).MarshalDriverCardFile(parsed); err == nil {
		t.Fatal("silently emitted semantic file without original signatures")
	}
}

func TestHistoricalTailToleranceDoesNotValidateComplete(t *testing.T) {
	if records, err := (UnmarshalOptions{}).unmarshalEventsData(make([]byte, 25)); err != nil || len(records.GetEvents()) != 1 {
		t.Fatal("historical tolerance changed")
	}
	raw := completeTestCard(t)
	for _, r := range raw.GetRecords() {
		if r.GetTag() == 0x050202 {
			r.SetValue(append(r.GetValue(), 0))
			break
		}
	}
	if err := ValidateCompleteDownload(raw, "G2V2"); err == nil {
		t.Fatal("complete download accepted event tail")
	}
}

func TestCvcRejectsTailsAndIncompleteSignatures(t *testing.T) {
	fixture, err := testcard.New("G2V2")
	if err != nil {
		t.Fatal(err)
	}
	cert := fixture.Files[0xc10102]
	if err := validateDownloadEccCertificate(cert); err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{cert[:len(cert)-1], append(bytes.Clone(cert), 0), make([]byte, len(cert))} {
		if err := validateDownloadEccCertificate(b); err == nil {
			t.Fatal("accepted incomplete CVC")
		}
	}
}
