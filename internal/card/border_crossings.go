package card

import (
	"encoding/binary"
	"fmt"

	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
)

// unmarshalBorderCrossings parses the EF_Border_Crossings file.
//
// The data type `CardBorderCrossings` is specified in the Data Dictionary, Section 2.11a.
//
// ASN.1 Definition:
//
//	CardBorderCrossings ::= SEQUENCE {
//	    borderCrossingPointerNewestRecord INTEGER (0..NoOfBorderCrossingRecords -1),
//	    cardBorderCrossingRecords SET SIZE (NoOfBorderCrossingRecords) OF CardBorderCrossingRecord
//	}
//
// Normative G2V2 layout: uint16 BE pointer followed by 17-byte records.
// Historical one-byte fixtures remain readable here. ValidateCompleteDownload
// requires the normative layout and exact advertised capacity before publication.
func (opts UnmarshalOptions) unmarshalBorderCrossings(data []byte) (*cardv1.BorderCrossings, error) {
	const (
		lenRecord = 17
	)

	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for CardBorderCrossings")
	}

	// Heuristic to determine pointer size:
	// Try 1 byte pointer
	rem1 := (len(data) - 1) % lenRecord
	// Try 2 byte pointer
	rem2 := (len(data) - 2) % lenRecord

	var pointerSize int
	if rem1 == 0 && rem2 != 0 {
		pointerSize = 1
	} else if rem2 == 0 && rem1 != 0 {
		pointerSize = 2
	} else {
		// Empty historical buffers may consist of just their pointer.
		if len(data) == 1 {
			pointerSize = 1
		} else if len(data) == 2 {
			pointerSize = 2
		} else {
			return nil, fmt.Errorf("invalid data length for CardBorderCrossings: %d (not 1+N*17 or 2+N*17)", len(data))
		}
	}

	// Parse pointer
	var newestRecordIndex int32
	if pointerSize == 1 {
		newestRecordIndex = int32(data[0])
	} else {
		newestRecordIndex = int32(binary.BigEndian.Uint16(data[0:2]))
	}

	target := &cardv1.BorderCrossings{}
	target.SetNewestRecordIndex(newestRecordIndex)

	// Parse records
	recordsData := data[pointerSize:]
	count := len(recordsData) / lenRecord
	targetRecords := make([]*cardv1.BorderCrossings_Record, count)

	for i := 0; i < count; i++ {
		start := i * lenRecord
		end := start + lenRecord
		recordData := recordsData[start:end]

		ddRecord, err := opts.UnmarshalCardBorderCrossingRecord(recordData)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record %d: %w", i, err)
		}

		record := &cardv1.BorderCrossings_Record{}
		record.SetCountryLeft(ddRecord.GetCountryLeft())
		record.SetCountryEntered(ddRecord.GetCountryEntered())
		record.SetGnssPlaceAuthRecord(ddRecord.GetGnssPlaceAuthRecord())
		record.SetVehicleOdometerKm(ddRecord.GetVehicleOdometerKm())
		targetRecords[i] = record
	}
	target.SetRecords(targetRecords)

	return target, nil
}

// MarshalCardBorderCrossings marshals the EF_Border_Crossings file.
func (opts MarshalOptions) MarshalCardBorderCrossings(msg *cardv1.BorderCrossings) ([]byte, error) {
	if msg == nil {
		return nil, nil
	}

	index := msg.GetNewestRecordIndex()
	if index < 0 || index > 65535 {
		return nil, fmt.Errorf("border pointer outside uint16 range")
	}
	data := binary.BigEndian.AppendUint16(nil, uint16(index))

	for _, record := range msg.GetRecords() {
		ddRecord := &ddv1.CardBorderCrossingRecord{}
		ddRecord.SetCountryLeft(record.GetCountryLeft())
		ddRecord.SetCountryEntered(record.GetCountryEntered())
		ddRecord.SetGnssPlaceAuthRecord(record.GetGnssPlaceAuthRecord())
		ddRecord.SetVehicleOdometerKm(record.GetVehicleOdometerKm())

		bytes, err := opts.MarshalCardBorderCrossingRecord(ddRecord)
		if err != nil {
			return nil, err
		}
		data = append(data, bytes...)
	}

	return data, nil
}
