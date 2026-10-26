package card

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
)

func TestApplicationIdentificationV2Layouts(t *testing.T) {
	for _, cardType := range []cardv1.CardType{cardv1.CardType_DRIVER_CARD, cardv1.CardType_WORKSHOP_CARD, cardv1.CardType_CONTROL_CARD, cardv1.CardType_COMPANY_CARD} {
		t.Run(cardType.String(), func(t *testing.T) {
			data := []byte{0, 8, 4, 0x60, 6, 0x58, 1, 0x50, 0x0c, 0}
			if cardType == cardv1.CardType_CONTROL_CARD || cardType == cardv1.CardType_COMPANY_CARD {
				data = []byte{0, 2, 0x0c, 0}
			}
			value, err := (UnmarshalOptions{}).unmarshalApplicationIdentificationV2(data, cardType)
			if err != nil {
				t.Fatal(err)
			}
			if value.GetCardType() != cardType {
				t.Fatalf("wrong type: %v", value.GetCardType())
			}
			var fields []int32
			switch cardType {
			case cardv1.CardType_DRIVER_CARD:
				v := value.GetDriver()
				fields = []int32{v.GetLengthOfFollowingData(), v.GetBorderCrossingRecordsCount(), v.GetLoadUnloadRecordsCount(), v.GetLoadTypeEntryRecordsCount(), v.GetVuConfigurationLengthRange()}
			case cardv1.CardType_WORKSHOP_CARD:
				v := value.GetWorkshop()
				fields = []int32{v.GetLengthOfFollowingData(), v.GetBorderCrossingRecordsCount(), v.GetLoadUnloadRecordsCount(), v.GetLoadTypeEntryRecordsCount(), v.GetVuConfigurationLengthRange()}
			case cardv1.CardType_CONTROL_CARD:
				fields = []int32{value.GetControl().GetLengthOfFollowingData(), value.GetControl().GetVuConfigurationLengthRange()}
			case cardv1.CardType_COMPANY_CARD:
				fields = []int32{value.GetCompany().GetLengthOfFollowingData(), value.GetCompany().GetVuConfigurationLengthRange()}
			}
			want := []int32{8, 1120, 1624, 336, 3072}
			if len(data) == 4 {
				want = []int32{2, 3072}
			}
			if diff := cmp.Diff(want, fields); diff != "" {
				t.Fatal(diff)
			}
			encoded, err := (MarshalOptions{}).MarshalCardApplicationIdentificationV2(value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, encoded) {
				t.Fatalf("round trip: %x != %x", encoded, data)
			}
			for length := 0; length < len(data); length++ {
				if _, err := (UnmarshalOptions{}).unmarshalApplicationIdentificationV2(data[:length], cardType); err == nil {
					t.Fatalf("accepted truncation %d", length)
				}
			}
			bad := append([]byte(nil), data...)
			binary.BigEndian.PutUint16(bad[:2], uint16(len(data)))
			if _, err := (UnmarshalOptions{}).unmarshalApplicationIdentificationV2(bad, cardType); err == nil {
				t.Fatal("accepted bad following length")
			}
			future := append(append([]byte(nil), data...), 0, 0)
			binary.BigEndian.PutUint16(future[:2], uint16(len(future)-2))
			if _, err := (UnmarshalOptions{}).unmarshalApplicationIdentificationV2(future, cardType); err == nil {
				t.Fatal("silently discarded future fields")
			}
		})
	}
}

func TestApplicationIdentificationV2UnknownAndInvalidMarshal(t *testing.T) {
	if _, err := (UnmarshalOptions{}).unmarshalApplicationIdentificationV2(make([]byte, 10), cardv1.CardType_CARD_TYPE_UNSPECIFIED); err == nil {
		t.Fatal("guessed card type")
	}
	for _, n := range []int32{-1, 65536} {
		v, err := (UnmarshalOptions{}).unmarshalApplicationIdentificationV2([]byte{0, 8, 0, 1, 0, 2, 0, 3, 0, 4}, cardv1.CardType_DRIVER_CARD)
		if err != nil {
			t.Fatal(err)
		}
		v.GetDriver().SetBorderCrossingRecordsCount(n)
		if _, err := (MarshalOptions{}).MarshalCardApplicationIdentificationV2(v); err == nil {
			t.Fatal("narrowed out-of-range capacity")
		}
	}
	v := &cardv1.ApplicationIdentificationV2{}
	v.SetCardType(cardv1.CardType_DRIVER_CARD)
	v.SetDriver(&cardv1.ApplicationIdentificationV2_Driver{})
	if _, err := (MarshalOptions{}).MarshalCardApplicationIdentificationV2(v); err == nil {
		t.Fatal("invented missing fields")
	}
}

func TestApplicationIdentificationV2CallerKeepsApplicationAndSource(t *testing.T) {
	app := make([]byte, 17)
	copy(app, []byte{1, 1, 1})
	v2 := []byte{0, 8, 4, 0x60, 6, 0x58, 1, 0x50, 0x0c, 0}
	block := func(fid uint16, appendix byte, data []byte) []byte {
		b := binary.BigEndian.AppendUint16(nil, fid)
		b = append(b, appendix)
		b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
		return append(b, data...)
	}
	// EF 0525 precedes 0501: application lookup must be independent of TLV order.
	data := append(block(0x0525, 2, v2), block(0x0525, 3, bytes.Repeat([]byte{0x5a}, 64))...)
	data = append(data, block(0x0501, 2, app)...)
	raw, err := (UnmarshalOptions{Strict: true}).UnmarshalRawCardFile(data)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := (ParseOptions{PreserveRawData: true}).ParseRawDriverCardFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.GetTachographG2().GetApplicationIdentificationV2().GetDriver().GetBorderCrossingRecordsCount() != 1120 {
		t.Fatal("wrong capacity")
	}
	if len(parsed.GetTachographG2().GetApplicationIdentificationV2().GetSignature()) != 64 {
		t.Fatal("signature lost")
	}
	if raw.GetRecords()[0].GetGeneration() != ddv1.Generation_GENERATION_2 || !bytes.Equal(raw.GetRecords()[0].GetValue(), v2) {
		t.Fatal("raw source lost")
	}
	encoded, err := (MarshalOptions{}).MarshalRawCardFile(raw)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("raw TLV round trip lost bytes")
	}
	app[0] = 4 // COMPANY must never become DRIVER through EF 0525.
	raw.GetRecords()[2].SetValue(app)
	if _, err := (ParseOptions{}).ParseRawDriverCardFile(raw); err == nil {
		t.Fatal("company interpreted as driver")
	}
}
