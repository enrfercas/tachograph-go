package card

import (
	"encoding/binary"
	"fmt"

	"github.com/way-platform/tachograph-go/internal/dd"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
)

// G2V2 cyclic EFs use a two-byte big-endian pointer, regardless of the
// pointer's current value. The complete-download validator also checks the
// allocated record count against Application_Identification[_V2].
func cyclicRecords(data []byte, recordSize int) (int32, [][]byte, error) {
	if len(data) < 2 || (len(data)-2)%recordSize != 0 {
		return 0, nil, fmt.Errorf("truncated cyclic EF: length %d, record size %d", len(data), recordSize)
	}
	count := (len(data) - 2) / recordSize
	index := int(binary.BigEndian.Uint16(data))
	if (count == 0 && index != 0) || (count > 0 && index >= count) {
		return 0, nil, fmt.Errorf("cyclic EF pointer %d outside %d records", index, count)
	}
	records := make([][]byte, count)
	for i := range records {
		records[i] = data[2+i*recordSize : 2+(i+1)*recordSize]
	}
	return int32(index), records, nil
}

// RawCardFile.Record remains the authoritative original EF, including its
// application tag, signature and authentication. These older protobuf types
// lack raw/signature fields; unknown enum bytes are retained there and left
// absent in the semantic message, rather than mapped to an invented value.
func (opts UnmarshalOptions) unmarshalPlacesAuthentication(data []byte) (*cardv1.PlacesAuthentication, error) {
	index, records, err := cyclicRecords(data, 5)
	if err != nil {
		return nil, err
	}
	result := &cardv1.PlacesAuthentication{}
	result.SetNewestRecordIndex(index)
	for _, b := range records {
		r := &cardv1.PlacesAuthentication_Record{}
		t, err := opts.UnmarshalTimeReal(b[:4])
		if err != nil {
			return nil, err
		}
		r.SetEntryTime(t)
		if status, err := dd.UnmarshalEnum[ddv1.PositionAuthenticationStatus](b[4]); err == nil {
			r.SetAuthenticationStatus(status)
		}
		result.SetRecords(append(result.GetRecords(), r))
	}
	return result, nil
}

func (opts UnmarshalOptions) unmarshalGnssPlacesAuthentication(data []byte) (*cardv1.GnssPlacesAuthentication, error) {
	index, records, err := cyclicRecords(data, 5)
	if err != nil {
		return nil, err
	}
	result := &cardv1.GnssPlacesAuthentication{}
	result.SetNewestRecordIndex(index)
	for _, b := range records {
		r := &cardv1.GnssPlacesAuthentication_Record{}
		t, err := opts.UnmarshalTimeReal(b[:4])
		if err != nil {
			return nil, err
		}
		r.SetTimestamp(t)
		if status, err := dd.UnmarshalEnum[ddv1.PositionAuthenticationStatus](b[4]); err == nil {
			r.SetAuthenticationStatus(status)
		}
		result.SetRecords(append(result.GetRecords(), r))
	}
	return result, nil
}

func (opts UnmarshalOptions) unmarshalLoadUnloadOperations(data []byte) (*cardv1.LoadUnloadOperations, error) {
	index, records, err := cyclicRecords(data, 20)
	if err != nil {
		return nil, err
	}
	result := &cardv1.LoadUnloadOperations{}
	result.SetNewestRecordIndex(index)
	for _, b := range records {
		r := &cardv1.LoadUnloadOperations_Record{}
		t, err := opts.UnmarshalTimeReal(b[:4])
		if err != nil {
			return nil, err
		}
		r.SetTimestamp(t)
		if operation, err := dd.UnmarshalEnum[ddv1.OperationType](b[4]); err == nil {
			r.SetOperationType(operation)
		}
		place, err := opts.UnmarshalGNSSPlaceAuthRecord(b[5:17])
		if err != nil {
			return nil, err
		}
		r.SetGnssPlaceAuthRecord(place)
		r.SetVehicleOdometerKm(int32(b[17])<<16 | int32(b[18])<<8 | int32(b[19]))
		result.SetRecords(append(result.GetRecords(), r))
	}
	return result, nil
}

func (opts UnmarshalOptions) unmarshalLoadTypeEntries(data []byte) (*cardv1.LoadTypeEntries, error) {
	index, records, err := cyclicRecords(data, 5)
	if err != nil {
		return nil, err
	}
	result := &cardv1.LoadTypeEntries{}
	result.SetNewestRecordIndex(index)
	for _, b := range records {
		r := &cardv1.LoadTypeEntries_Record{}
		t, err := opts.UnmarshalTimeReal(b[:4])
		if err != nil {
			return nil, err
		}
		r.SetTimestamp(t)
		if load, err := dd.UnmarshalEnum[ddv1.LoadType](b[4]); err == nil {
			r.SetLoadTypeEntered(load)
		}
		result.SetRecords(append(result.GetRecords(), r))
	}
	return result, nil
}
