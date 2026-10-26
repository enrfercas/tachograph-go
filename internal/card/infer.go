package card

import (
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// InferFileType determines the card type from raw card data.
func InferFileType(input *cardv1.RawCardFile) cardv1.CardType {
	// The File field is already set during raw parsing, so we can use the records directly
	enumDesc := cardv1.CardType_CARD_TYPE_UNSPECIFIED.Descriptor()
	for i := 0; i < enumDesc.Values().Len(); i++ {
		enumValue := enumDesc.Values().Get(i)
		fileStructure, ok := proto.GetExtension(enumValue.Options(), cardv1.E_FileStructure).(*cardv1.FileDescriptor)
		if !ok {
			continue
		}
		if hasAllElementaryFiles(fileStructure, input.GetRecords()) {
			return cardv1.CardType(enumValue.Number())
		}
	}
	return cardv1.CardType_CARD_TYPE_UNSPECIFIED
}

// HasDriverApplicationEvidence recognizes only known DRIVER layouts/versions.
// Conflicting card types or duplicate application identities are ambiguous.
func HasDriverApplicationEvidence(input *cardv1.RawCardFile) bool {
	found := false
	seen := map[int32]bool{}
	for _, r := range input.GetRecords() {
		if r.GetFile() != cardv1.ElementaryFileType_EF_APPLICATION_IDENTIFICATION || r.GetContentType() != cardv1.ContentType_DATA {
			continue
		}
		b := r.GetValue()
		tag := r.GetTag()
		if seen[tag] {
			return false
		}
		seen[tag] = true
		if len(b) == 10 && tag&255 == 0 && b[0] == 1 && b[1] == 0 && b[2] == 0 {
			found = true
			continue
		}
		if len(b) == 17 && tag&255 == 2 && b[0] == 1 && b[1] == 1 && (b[2] == 0 || b[2] == 1) {
			found = true
			continue
		}
		return false
	}
	return found
}

// mapFidToElementaryFileType maps a FID to its ElementaryFileType using protobuf annotations.
// Returns the file type and true if found, or ELEMENTARY_FILE_UNSPECIFIED and false if not found.
func mapFidToElementaryFileType(fid uint16, generation ddv1.Generation) (cardv1.ElementaryFileType, bool) {
	// Handle ambiguous File IDs based on generation
	if fid == 0xC100 {
		if generation == ddv1.Generation_GENERATION_2 {
			return cardv1.ElementaryFileType_EF_CARD_MA_CERTIFICATE, true
		}
		return cardv1.ElementaryFileType_EF_CARD_CERTIFICATE, true
	}

	enumDesc := cardv1.ElementaryFileType_ELEMENTARY_FILE_UNSPECIFIED.Descriptor()
	for i := 0; i < enumDesc.Values().Len(); i++ {
		enumValue := enumDesc.Values().Get(i)
		fileId, ok := proto.GetExtension(enumValue.Options(), cardv1.E_FileId).(int32)
		if !ok {
			continue
		}
		if uint16(fileId) == fid {
			// Skip EF_CARD_MA_CERTIFICATE in the loop since it's handled explicitly above
			// to prioritize EF_CARD_CERTIFICATE for Gen1 (or unspecified) if we rely on the loop for others.
			// However, since we handle 0xC100 explicitly, we can just return if we find a match
			// that isn't one of the ambiguous ones, OR just let the explicit check handle it.
			// The loop will find *one* of them (likely the first one defined in proto if we don't skip).
			// To be safe and efficient, we rely on the explicit check above.
			return cardv1.ElementaryFileType(enumValue.Number()), true
		}
	}
	return cardv1.ElementaryFileType_ELEMENTARY_FILE_UNSPECIFIED, false
}

// getFileId maps an ElementaryFileType to its FID using protobuf annotations.
// Returns the FID and true if found, or 0 and false if not found.
func getFileId(fileType cardv1.ElementaryFileType) (uint16, bool) {
	enumDesc := cardv1.ElementaryFileType_ELEMENTARY_FILE_UNSPECIFIED.Descriptor()
	enumValue := enumDesc.Values().ByNumber(protoreflect.EnumNumber(fileType))
	if enumValue == nil {
		return 0, false
	}
	fileId, ok := proto.GetExtension(enumValue.Options(), cardv1.E_FileId).(int32)
	if !ok {
		return 0, false
	}
	return uint16(fileId), true
}

// hasAllElementaryFiles checks if all required elementary files are present
func hasAllElementaryFiles(fileStructure *cardv1.FileDescriptor, records []*cardv1.RawCardFile_Record) bool {
	// Get all elementary files that should be present for this card type
	expectedFiles := getAllElementaryFiles(fileStructure)

	// Check if all present files are expected for this card type
	for _, record := range records {
		if record.GetContentType() == cardv1.ContentType_DATA {
			found := false
			for _, expectedFile := range expectedFiles {
				if record.GetFile() == expectedFile {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// getAllElementaryFiles extracts all elementary files from a file structure
func getAllElementaryFiles(desc *cardv1.FileDescriptor) []cardv1.ElementaryFileType {
	var files []cardv1.ElementaryFileType
	if desc.GetType() == cardv1.FileType_EF {
		files = append(files, desc.GetEf())
	}
	for _, child := range desc.GetFiles() {
		files = append(files, getAllElementaryFiles(child)...)
	}
	return files
}
