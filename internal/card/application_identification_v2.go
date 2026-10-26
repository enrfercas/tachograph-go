package card

import (
	"encoding/binary"
	"fmt"

	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
)

// Appendix 1 sections 2.48a, 2.50a, 2.61a and 2.234a (2021/1228).
// A type comes from Application_Identification in the same DF, never EF size.
func applicationIdentificationV2Size(cardType cardv1.CardType) (int, error) {
	switch cardType {
	case cardv1.CardType_DRIVER_CARD, cardv1.CardType_WORKSHOP_CARD:
		return 10, nil
	case cardv1.CardType_CONTROL_CARD, cardv1.CardType_COMPANY_CARD:
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported Application_Identification_V2 card type: %v", cardType)
	}
}

// unmarshalApplicationIdentificationV2 decodes the known EF 0525 layouts.
// DRIVER/WORKSHOP: lengthOfFollowingData, border, load/unload, load type and VU
// configuration capacities, each uint16 BE. CONTROL/COMPANY: length and VU
// configuration capacity, each uint16 BE. Unknown/future layouts fail explicitly;
// RawCardFile.Record retains original bytes, tag, signature and provenance.
func (opts UnmarshalOptions) unmarshalApplicationIdentificationV2(data []byte, cardType cardv1.CardType) (*cardv1.ApplicationIdentificationV2, error) {
	expected, err := applicationIdentificationV2Size(cardType)
	if err != nil {
		return nil, err
	}
	if len(data) != expected {
		return nil, fmt.Errorf("unsupported or truncated Application_Identification_V2 for %v: got %d bytes, want %d", cardType, len(data), expected)
	}
	following := int(binary.BigEndian.Uint16(data[:2]))
	if following != len(data)-2 {
		return nil, fmt.Errorf("Application_Identification_V2 lengthOfFollowingData: got %d, want %d", following, len(data)-2)
	}
	field := func(offset int) int32 { return int32(binary.BigEndian.Uint16(data[offset : offset+2])) }
	target := &cardv1.ApplicationIdentificationV2{}
	target.SetCardType(cardType)
	switch cardType {
	case cardv1.CardType_DRIVER_CARD:
		v := &cardv1.ApplicationIdentificationV2_Driver{}
		v.SetLengthOfFollowingData(field(0))
		v.SetBorderCrossingRecordsCount(field(2))
		v.SetLoadUnloadRecordsCount(field(4))
		v.SetLoadTypeEntryRecordsCount(field(6))
		v.SetVuConfigurationLengthRange(field(8))
		target.SetDriver(v)
	case cardv1.CardType_WORKSHOP_CARD:
		v := &cardv1.ApplicationIdentificationV2_Workshop{}
		v.SetLengthOfFollowingData(field(0))
		v.SetBorderCrossingRecordsCount(field(2))
		v.SetLoadUnloadRecordsCount(field(4))
		v.SetLoadTypeEntryRecordsCount(field(6))
		v.SetVuConfigurationLengthRange(field(8))
		target.SetWorkshop(v)
	case cardv1.CardType_CONTROL_CARD:
		v := &cardv1.ApplicationIdentificationV2_Control{}
		v.SetLengthOfFollowingData(field(0))
		v.SetVuConfigurationLengthRange(field(2))
		target.SetControl(v)
	case cardv1.CardType_COMPANY_CARD:
		v := &cardv1.ApplicationIdentificationV2_Company{}
		v.SetLengthOfFollowingData(field(0))
		v.SetVuConfigurationLengthRange(field(2))
		target.SetCompany(v)
	}
	return target, nil
}

// MarshalCardApplicationIdentificationV2 is the inverse for the four known
// layouts. It never fills absent fields or narrows uint16 counters to a byte.
// Other card file parsers remain unsupported; this is only their EF 0525 codec.
func (opts MarshalOptions) MarshalCardApplicationIdentificationV2(app *cardv1.ApplicationIdentificationV2) ([]byte, error) {
	if app == nil {
		return nil, nil
	}
	expected, err := applicationIdentificationV2Size(app.GetCardType())
	if err != nil {
		return nil, err
	}
	var fields []int32
	switch app.GetCardType() {
	case cardv1.CardType_DRIVER_CARD:
		v := app.GetDriver()
		if v == nil || !v.HasLengthOfFollowingData() || !v.HasBorderCrossingRecordsCount() || !v.HasLoadUnloadRecordsCount() || !v.HasLoadTypeEntryRecordsCount() || !v.HasVuConfigurationLengthRange() {
			return nil, fmt.Errorf("missing DRIVER Application_Identification_V2 fields")
		}
		fields = []int32{v.GetLengthOfFollowingData(), v.GetBorderCrossingRecordsCount(), v.GetLoadUnloadRecordsCount(), v.GetLoadTypeEntryRecordsCount(), v.GetVuConfigurationLengthRange()}
	case cardv1.CardType_WORKSHOP_CARD:
		v := app.GetWorkshop()
		if v == nil || !v.HasLengthOfFollowingData() || !v.HasBorderCrossingRecordsCount() || !v.HasLoadUnloadRecordsCount() || !v.HasLoadTypeEntryRecordsCount() || !v.HasVuConfigurationLengthRange() {
			return nil, fmt.Errorf("missing WORKSHOP Application_Identification_V2 fields")
		}
		fields = []int32{v.GetLengthOfFollowingData(), v.GetBorderCrossingRecordsCount(), v.GetLoadUnloadRecordsCount(), v.GetLoadTypeEntryRecordsCount(), v.GetVuConfigurationLengthRange()}
	case cardv1.CardType_CONTROL_CARD:
		v := app.GetControl()
		if v == nil || !v.HasLengthOfFollowingData() || !v.HasVuConfigurationLengthRange() {
			return nil, fmt.Errorf("missing CONTROL Application_Identification_V2 fields")
		}
		fields = []int32{v.GetLengthOfFollowingData(), v.GetVuConfigurationLengthRange()}
	case cardv1.CardType_COMPANY_CARD:
		v := app.GetCompany()
		if v == nil || !v.HasLengthOfFollowingData() || !v.HasVuConfigurationLengthRange() {
			return nil, fmt.Errorf("missing COMPANY Application_Identification_V2 fields")
		}
		fields = []int32{v.GetLengthOfFollowingData(), v.GetVuConfigurationLengthRange()}
	}
	if fields[0] != int32(expected-2) {
		return nil, fmt.Errorf("invalid Application_Identification_V2 lengthOfFollowingData: %d", fields[0])
	}
	result := make([]byte, 0, expected)
	for _, value := range fields {
		if value < 0 || value > 65535 {
			return nil, fmt.Errorf("Application_Identification_V2 value outside uint16: %d", value)
		}
		result = binary.BigEndian.AppendUint16(result, uint16(value))
	}
	return result, nil
}
