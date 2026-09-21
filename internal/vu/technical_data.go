package vu

import (
	"fmt"

	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
)

// ===== sizeOf Functions =====

// sizeOfTechnicalData dispatches to generation-specific size calculation.
func sizeOfTechnicalData(data []byte, transferType vuv1.TransferType) (totalSize, signatureSize int, err error) {
	switch transferType {
	case vuv1.TransferType_TECHNICAL_DATA_GEN1:
		return sizeOfTechnicalDataGen1(data)
	case vuv1.TransferType_TECHNICAL_DATA_GEN2_V1:
		return sizeOfTechnicalDataGen2V1(data)
	case vuv1.TransferType_TECHNICAL_DATA_GEN2_V2:
		return sizeOfTechnicalDataGen2V2(data)
	default:
		return 0, 0, fmt.Errorf("unsupported transfer type for TechnicalData: %v", transferType)
	}
}

// sizeOfTechnicalDataGen1 calculates total size for Gen1 Technical Data including signature.
//
// Technical Data Gen1 structure (from Appendix 7, Section 2.2.6.6):
// - VuIdentification (Data Dictionary 2.205): 116 bytes
//   - vuManufacturerName: Name = 36 bytes (1 codepage + 35 bytes)
//   - vuManufacturerAddress: Address = 36 bytes (1 codepage + 35 bytes)
//   - vuPartNumber: 16 bytes
//   - vuSerialNumber: ExtendedSerialNumber = 8 bytes (4+2+1+1)
//   - vuSoftwareIdentification: 8 bytes (VuSoftwareVersion 4 + VuSoftInstallationDate 4)
//   - vuManufacturingDate: TimeReal = 4 bytes
//   - vuApprovalNumber: IA5String(SIZE(8)) = 8 bytes
//
// - SensorPaired: 20 bytes
//   - sensorSerialNumber: ExtendedSerialNumber = 8 bytes
//   - sensorApprovalNumber: 8 bytes (Gen1 SIZE(8))
//   - sensorPairingDateFirst: TimeReal = 4 bytes
//
// - VuCalibrationData (Data Dictionary 2.173): 1 byte + (noOfVuCalibrationRecords * 167 bytes)
//   - noOfVuCalibrationRecords: 1 byte
//   - vuCalibrationRecords: SET OF VuCalibrationRecordFirstGen
//   - VuCalibrationRecordFirstGen (Data Dictionary 2.174): 167 bytes
//   - calibrationPurpose: 1 byte
//   - workshopName: Name = 36 bytes
//   - workshopAddress: Address = 36 bytes
//   - workshopCardNumber: FullCardNumber = 18 bytes
//   - workshopCardExpiryDate: TimeReal = 4 bytes
//   - vehicleIdentificationNumber: 17 bytes
//   - vehicleRegistrationIdentification: 15 bytes (1+1+13)
//   - wVehicleCharacteristicConstant: 2 bytes
//   - kConstantOfRecordingEquipment: 2 bytes
//   - lTyreCircumference: 2 bytes
//   - tyreSize: 15 bytes
//   - authorisedSpeed: 1 byte
//   - oldOdometerValue: 3 bytes
//   - newOdometerValue: 3 bytes
//   - oldTimeValue: TimeReal = 4 bytes
//   - newTimeValue: TimeReal = 4 bytes
//   - nextCalibrationDate: TimeReal = 4 bytes
//
// - Signature: 128 bytes (RSA)
func sizeOfTechnicalDataGen1(data []byte) (totalSize, signatureSize int, err error) {
	offset := 0

	// VuIdentification: 116 bytes (fixed structure, per Data Dictionary 2.205)
	offset += 116

	// SensorPaired: 20 bytes (fixed structure)
	offset += 20

	// VuCalibrationData: 1 byte count + variable calibration records
	if len(data[offset:]) < 1 {
		return 0, 0, fmt.Errorf("insufficient data for noOfVuCalibrationRecords")
	}
	noOfVuCalibrationRecords := data[offset]
	offset += 1

	// Each VuCalibrationRecordFirstGen: 167 bytes (per Data Dictionary 2.174)
	const vuCalibrationRecordSize = 167
	offset += int(noOfVuCalibrationRecords) * vuCalibrationRecordSize

	// Signature: 128 bytes for Gen1 RSA
	const gen1SignatureSize = 128
	offset += gen1SignatureSize

	return offset, gen1SignatureSize, nil
}

// sizeOfTechnicalDataGen2V1 calculates size by parsing all Gen2 V1 RecordArrays.
func sizeOfTechnicalDataGen2V1(data []byte) (totalSize, signatureSize int, err error) {
	return sizeOfTechnicalDataGen2Compatible(data, 4)
}

func sizeOfTechnicalDataGen2V2(data []byte) (totalSize, signatureSize int, err error) {
	return sizeOfTechnicalDataGen2Compatible(data, 7)
}

func sizeOfTechnicalDataGen2Compatible(data []byte, legacyArrayCount int) (totalSize, signatureSize int, err error) {
	const (
		signatureRecordType = byte(0x08)
		maxSpecArrays       = 8
	)

	offset := 0

	// First prefer the standards-compliant layout. RecordType 0x08 is Signature.
	// We do not assume a fixed ECC signature byte length here because it depends
	// on the curve; the RecordArray header already declares the record size.
	for index := 0; index < maxSpecArrays; index++ {
		recordType, recordSize, noOfRecords, _, headerErr := parseRecordArrayHeader(data, offset)
		if headerErr != nil {
			break
		}

		size, sizeErr := sizeOfRecordArray(data, offset)
		if sizeErr != nil {
			return 0, 0, fmt.Errorf("TechnicalData RecordArray index=%d: %w", index, sizeErr)
		}
		if size < 5 || offset+size > len(data) {
			return 0, 0, fmt.Errorf(
				"TechnicalData RecordArray index=%d exceeds input: offset=%d size=%d len=%d",
				index,
				offset,
				size,
				len(data),
			)
		}

		if recordType == signatureRecordType {
			// Real downloads contain one signature. Allow an empty placeholder too,
			// because anonymized/generated test material may omit the signature bytes.
			if noOfRecords != 1 && !(noOfRecords == 0 && recordSize == 0) {
				return 0, 0, fmt.Errorf(
					"SignatureRecordArray has invalid record count %d",
					noOfRecords,
				)
			}
			return offset + size, size, nil
		}

		offset += size
	}

	// Compatibility fallback for the old tachograph-go v0.17.3 fixtures/model.
	// V1 expected 4 arrays and V2 expected 7 arrays, with the last one treated as
	// the signature even though those fixtures do not use RecordType 0x08.
	offset = 0
	lastSize := 0
	for index := 0; index < legacyArrayCount; index++ {
		size, sizeErr := sizeOfRecordArray(data, offset)
		if sizeErr != nil {
			return 0, 0, fmt.Errorf(
				"legacy TechnicalData RecordArray index=%d: %w",
				index,
				sizeErr,
			)
		}
		if size < 5 || offset+size > len(data) {
			return 0, 0, fmt.Errorf(
				"legacy TechnicalData RecordArray index=%d exceeds input: offset=%d size=%d len=%d",
				index,
				offset,
				size,
				len(data),
			)
		}
		lastSize = size
		offset += size
	}

	return offset, lastSize, nil
}

// AppendVuTechnicalData appends VU technical data to a buffer.
//
// The data type `VuTechnicalData` is specified in the Data Dictionary, Section 2.2.6.5.
//
// ASN.1 Definition:
//
//	VuTechnicalDataFirstGen ::= SEQUENCE {
//	    vuIdentification                  VuIdentification,
//	    vuCalibrationData                 VuCalibrationData,
//	    vuCardData                        VuCardData,
//	    signature                         SignatureFirstGen
//	}
//
//	VuTechnicalDataSecondGen ::= SEQUENCE {
//	    vuIdentificationRecordArray       VuIdentificationRecordArray,
//	    vuCalibrationRecordArray          VuCalibrationRecordArray,
//	    vuCardRecordArray                 VuCardRecordArray,
//	    signatureRecordArray              SignatureRecordArray
//	}

// appendVuTechnicalDataBytes appends VU technical data to a byte slice
