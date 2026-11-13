package card

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
)

const MaxInspectionBytes = 64 << 20
const maxInspectionBlocks = 8192

type InspectionBlock struct {
	Offset              int    `json:"offset"`
	Tag                 int    `json:"tag"`
	FID                 int    `json:"fid"`
	Name                string `json:"name"`
	Application         string `json:"application"`
	ContentType         string `json:"contentType"`
	DeclaredLength      int    `json:"declaredLength"`
	AvailableLength     int    `json:"availableLength"`
	SignaturePresent    bool   `json:"signaturePresent"`
	Required            bool   `json:"required"`
	Absent              bool   `json:"absent"`
	StructuralStatus    string `json:"structuralStatus"`
	CryptographicStatus string `json:"cryptographicStatus"`
	Reason              string `json:"reason,omitempty"`
}

type DownloadInspection struct {
	Contract             string            `json:"contract"`
	EvaluationVersion    string            `json:"evaluationVersion"`
	SHA256               string            `json:"sha256"`
	Size                 int               `json:"size"`
	IsCard               bool              `json:"isCard"`
	Profile              DownloadProfile   `json:"profile"`
	AcceptanceStatus     string            `json:"acceptanceStatus"`
	InventoryStatus      string            `json:"inventoryStatus"`
	StructuralStatus     string            `json:"structuralStatus"`
	AuthenticityStatus   string            `json:"authenticityStatus"`
	PhysicalCompleteness string            `json:"physicalCompleteness"`
	Defects              []InventoryDefect `json:"defects"`
	Blocks               []InspectionBlock `json:"blocks"`
	StoppedOffset        *int              `json:"stoppedOffset,omitempty"`
	// Container provenance is supplied only by the containing application's
	// verified extraction routine. Payload bytes are never diagnostic log text.
	ContainerSHA256           string `json:"containerSha256,omitempty"`
	ContainerOffset           *int   `json:"containerOffset,omitempty"`
	ContainerExtractionFormat string `json:"containerExtractionFormat,omitempty"`
	EmbeddedPayload           []byte `json:"embeddedPayload,omitempty"`
}

func (i *DownloadInspection) Rejected() bool {
	return len(i.AcceptanceStatus) >= 8 && i.AcceptanceStatus[:8] == "INVALID_"
}

type InspectionOptions struct {
	AuthenticateOptions
	ExpectedGeneration  string
	ObservedCard        bool
	ObservedPresentTags []int
}

// InspectDownload never runs a semantic activity decoder, modifies input or
// invents missing bytes. It retains every recoverable TLV up to a hard bound.
func (o InspectionOptions) InspectDownload(ctx context.Context, input []byte) *DownloadInspection {
	hash := sha256.Sum256(input)
	r := &DownloadInspection{Contract: "card-integrity/v1", EvaluationVersion: "inventory-2026-11-13/v1", SHA256: hex.EncodeToString(hash[:]), Size: len(input), IsCard: true, AcceptanceStatus: "UNVERIFIED", InventoryStatus: "UNDETERMINED", StructuralStatus: "VALID", AuthenticityStatus: "UNVERIFIED", PhysicalCompleteness: "NOT_ASSESSED", Defects: []InventoryDefect{}, Blocks: []InspectionBlock{}}
	if len(input) > 0 && input[0] == 0x76 {
		r.IsCard = false
		r.AcceptanceStatus = "PROFILE_UNDETERMINED"
		return r
	}
	add := func(code, scope string, tag, offset int, reason string) {
		d := InventoryDefect{Name: EFName(tag), Code: code, Scope: scope, Tag: tag, FID: tag >> 8, Reason: reason}
		if tag != 0 {
			d.Application = ApplicationName(tag & 255)
		}
		if offset >= 0 {
			n := offset
			d.Offset = &n
		}
		r.Defects = append(r.Defects, d)
	}
	if len(input) > MaxInspectionBytes {
		add("inspection_size_limit", "structure", 0, 0, "")
		r.StructuralStatus = "INVALID"
		r.AcceptanceStatus = "INVALID_STRUCTURE"
		return r
	}
	raw := &cardv1.RawCardFile{}
	seen := map[int]bool{}
	previous := -1
	for offset := 0; offset < len(input); {
		if len(r.Blocks) >= maxInspectionBlocks {
			add("inspection_block_limit", "structure", 0, offset, "")
			r.StoppedOffset = &offset
			break
		}
		if len(input)-offset < 5 {
			add("tlv_header_truncated", "structure", 0, offset, "")
			r.StoppedOffset = &offset
			break
		}
		tag := int(input[offset])<<16 | int(input[offset+1])<<8 | int(input[offset+2])
		declared := int(binary.BigEndian.Uint16(input[offset+3:]))
		available := len(input) - offset - 5
		if available > declared {
			available = declared
		}
		b := InspectionBlock{Offset: offset, Tag: tag, FID: tag >> 8, Application: ApplicationName(tag & 255), DeclaredLength: declared, AvailableLength: available, ContentType: "DATA", StructuralStatus: "VALID", CryptographicStatus: "NOT_EVALUATED"}
		if tag&1 != 0 {
			b.ContentType = "SIGNATURE"
		}
		// The low-level decoder requires a complete payload; do not call it on
		// truncated input (the branch below constructs a visible partial row).
		if available < declared {
			b.Name = fmt.Sprintf("EF_%04X", tag>>8)
			b.StructuralStatus = "TRUNCATED"
			r.Blocks = append(r.Blocks, b)
			add("tlv_payload_truncated", "structure", tag, offset, "")
			n := offset + 5 + available
			r.StoppedOffset = &n
			break
		}
		record, err := unmarshalRawCardFileRecord(input[offset:offset+5+available], false)
		if err != nil {
			add("tlv_invalid", "structure", tag, offset, "")
			b.StructuralStatus = "INVALID"
			b.Reason = "tlv_invalid"
		} else {
			b.Name = EFName(tag)
			if record.GetFile() == cardv1.ElementaryFileType_ELEMENTARY_FILE_UNSPECIFIED {
				b.Reason = "unknown_ef"
				add("unknown_ef", "uncertainty", tag, offset, "")
			}
			raw.SetRecords(append(raw.GetRecords(), record))
		}
		if tag&255 > 3 || declared == 0 || declared == 65535 {
			add("tlv_length_or_appendix_invalid", "structure", tag, offset, "")
			b.StructuralStatus = "INVALID"
		}
		if seen[tag] {
			add("duplicate_tlv", "structure", tag, offset, "")
			b.StructuralStatus = "INVALID"
		}
		if tag&1 != 0 && previous != tag-1 {
			add("signature_association_invalid", "structure", tag, offset, "")
			b.StructuralStatus = "INVALID"
		}
		if tag&1 != 0 && (tag&2 == 0 && declared != 128 || tag&2 != 0 && declared != 64 && declared != 96 && declared != 128 && declared != 132) {
			add("signature_length_invalid", "structure", tag, offset, "")
			b.StructuralStatus = "INVALID"
		}
		seen[tag] = true
		previous = tag
		r.Blocks = append(r.Blocks, b)
		offset += 5 + declared
	}
	if len(input) == 0 {
		add("empty_acquisition", "structure", 0, 0, "")
	}
	r.Profile = ResolveDownloadProfile(raw, o.ExpectedGeneration, o.ObservedCard)
	if r.Profile.Determined {
		r.InventoryStatus = "COMPLETE"
	}
	inventory := InspectInventory(raw, r.Profile, o.ObservedPresentTags)
	r.Defects = append(r.Defects, inventory...)
	for _, d := range inventory {
		r.InventoryStatus = "INCOMPLETE"
		if d.Code == "required_ef_missing" || d.Code == "observed_required_ef_missing" {
			r.Blocks = append(r.Blocks, InspectionBlock{Tag: d.Tag, FID: d.FID, Name: d.Name, Application: d.Application, ContentType: "DATA", Required: true, Absent: true, StructuralStatus: "MISSING", CryptographicStatus: "NOT_EVALUATED", Reason: d.Code})
		}
	}
	// Reuse the PC/SC structural rules after the complete inventory is present.
	// Historical 050E and pre-V2 conditional link presence remain distinct from
	// a newly observed direct acquisition. No input bytes are synthesized.
	if r.Profile.Determined && len(inventory) == 0 && r.StoppedOffset == nil {
		if err := validateDownloadStructure(raw, r.Profile.Generation, r.Profile.RequireLink, !o.ObservedCard); err != nil {
			var ext *DownloadStructureError
			if errors.As(err, &ext) && ext.Unsupported {
				add(ext.Reason, "uncertainty", ext.Tag, -1, "")
			} else {
				add("download_structure_invalid", "structure", 0, -1, err.Error())
			}
		}
	}
	assessment := safeDownloadAssessment(ctx, o.AuthenticateOptions, raw)
	r.AuthenticityStatus = assessment.Status
	for _, issue := range assessment.Issues {
		r.Defects = append(r.Defects, InventoryDefect{Code: issue.Reason, Scope: "authenticity", Application: issue.Application, Reason: issue.Status})
	}
	for index := range r.Blocks {
		b := &r.Blocks[index]
		b.SignaturePresent = seen[b.Tag&^1|1]
		if b.ContentType != "DATA" || b.Absent {
			continue
		}
		for _, record := range raw.GetRecords() {
			if int(record.GetTag()) != b.Tag {
				continue
			}
			if !isSignedEF(record.GetFile()) {
				b.CryptographicStatus = "NOT_REQUIRED"
			} else if record.GetAuthentication() != nil {
				b.CryptographicStatus = record.GetAuthentication().GetStatus().String()
				if b.CryptographicStatus == "DATA_SIGNATURE_INVALID" {
					b.Reason = "data_signature_invalid"
					add("data_signature_invalid", "authenticity", b.Tag, b.Offset, "INVALID")
				}
			}
		}
		for _, d := range r.Defects {
			if d.Tag == b.Tag && d.Code == "required_signature_missing" {
				b.CryptographicStatus = "MISSING"
				b.Reason = d.Code
			}
		}
	}
	if o.ObservedCard {
		r.PhysicalCompleteness = "OBSERVED_PROFILE"
	}
	for _, d := range r.Defects {
		if d.Scope == "structure" {
			r.StructuralStatus = "INVALID"
		}
		if d.Code == "observed_required_ef_missing" {
			r.PhysicalCompleteness = "EXPECTED_FILES_NOT_FOUND"
		}
	}
	switch {
	case r.StructuralStatus == "INVALID":
		r.AcceptanceStatus = "INVALID_STRUCTURE"
	case containsDefect(r.Defects, "required_ef_missing") || containsDefect(r.Defects, "observed_required_ef_missing"):
		r.AcceptanceStatus = "INVALID_MISSING_REQUIRED_EF"
	case containsDefect(r.Defects, "required_signature_missing"):
		r.AcceptanceStatus = "INVALID_MISSING_REQUIRED_SIGNATURE"
		r.AuthenticityStatus = "MISSING"
	case assessment.Status == "INVALID":
		r.AcceptanceStatus = "INVALID_SIGNATURE"
	case !r.Profile.Determined || hasUncertainty(r.Defects):
		r.AcceptanceStatus = "PROFILE_UNDETERMINED"
	case assessment.Status == "VERIFIED":
		r.AcceptanceStatus = "VALID"
	default:
		r.AcceptanceStatus = "UNVERIFIED"
	}
	return r
}

func containsDefect(ds []InventoryDefect, code string) bool {
	for _, d := range ds {
		if d.Code == code {
			return true
		}
	}
	return false
}
func hasUncertainty(ds []InventoryDefect) bool {
	for _, d := range ds {
		if d.Scope == "uncertainty" {
			return true
		}
	}
	return false
}

func safeDownloadAssessment(ctx context.Context, o AuthenticateOptions, raw *cardv1.RawCardFile) (result AuthenticityAssessment) {
	defer func() {
		if recover() != nil {
			result = AuthenticityAssessment{Status: "UNVERIFIED", Issues: []AuthenticityIssue{{Status: "UNVERIFIED", Reason: "crypto_capability_or_encoding_unavailable"}}}
		}
	}()
	return o.AssessAuthenticity(ctx, raw)
}
