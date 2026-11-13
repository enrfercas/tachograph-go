package tachograph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/way-platform/tachograph-go/internal/card"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
)

// CardDownloadValidation is a versioned gate for a newly acquired PC/SC file.
// It never reports success from the analyzer's historical fallback path.
type CardDownloadValidation struct {
	Inspection           *CardFileInspection           `json:"inspection,omitempty"`
	Contract             string                        `json:"contract"`
	Generation           string                        `json:"generation"`
	SHA256               string                        `json:"sha256"`
	StructuralValid      bool                          `json:"structuralValid"`
	SemanticValid        bool                          `json:"semanticValid"`
	Cryptography         string                        `json:"cryptography"`
	RecordCount          int                           `json:"recordCount"`
	Profile              string                        `json:"profile"`
	AcquisitionStatus    AcquisitionStatus             `json:"acquisitionStatus"`
	StructuralStatus     StructuralStatus              `json:"structuralStatus"`
	AuthenticityStatus   AuthenticityStatus            `json:"authenticityStatus"`
	PhysicalCompleteness string                        `json:"physicalCompleteness"`
	Observations         []CardDownloadEFObservation   `json:"observations"`
	Issues               []CardDownloadValidationIssue `json:"issues"`
}

type AcquisitionStatus string

const (
	AcquisitionComplete   AcquisitionStatus = "COMPLETE"
	AcquisitionIncomplete AcquisitionStatus = "INCOMPLETE"
	AcquisitionFailed     AcquisitionStatus = "FAILED"
)

type StructuralStatus string

const (
	StructureValid       StructuralStatus = "VALID"
	StructureInvalid     StructuralStatus = "INVALID"
	StructureUnsupported StructuralStatus = "UNSUPPORTED"
)

type AuthenticityStatus string

const (
	AuthenticityVerified   AuthenticityStatus = "VERIFIED"
	AuthenticityUnverified AuthenticityStatus = "UNVERIFIED"
	AuthenticityInvalid    AuthenticityStatus = "INVALID"
	AuthenticityMissing    AuthenticityStatus = "MISSING"
)

type CardDownloadValidationIssue struct {
	Scope       string `json:"scope"`
	Code        string `json:"code"`
	Application string `json:"application,omitempty"`
}
type CardDownloadEFObservation struct {
	Tag         int    `json:"tag"`
	Requirement string `json:"requirement"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
}

type CardDownloadValidationOptions struct {
	// ExpectedGeneration must come from the application observed on the card.
	ExpectedGeneration  string
	CertificateResolver CertificateResolver
	// ObservedCard distinguishes PC/SC evidence from an old downloaded file.
	ObservedCard bool
}

// Validate assesses the Appendix 7 acquisition profile, structure, analysis
// capability and authenticity independently. Trust availability cannot turn a
// complete acquisition into an incomplete one or an unverified signature invalid.
// The caller must retain the original input; semantic messages alone cannot
// reconstruct signatures for the older G2V2 protobuf types.
func (o CardDownloadValidationOptions) Validate(ctx context.Context, input []byte) (*CardDownloadValidation, error) {
	sum := sha256.Sum256(input)
	result := &CardDownloadValidation{Contract: "pcsc-card-3/v1", Profile: "APPENDIX_7_DRIVER", Generation: o.ExpectedGeneration, SHA256: hex.EncodeToString(sum[:]), AcquisitionStatus: AcquisitionIncomplete, StructuralStatus: StructureInvalid, AuthenticityStatus: AuthenticityUnverified, Cryptography: "unverified", PhysicalCompleteness: "NOT_ASSESSED", Observations: []CardDownloadEFObservation{}, Issues: []CardDownloadValidationIssue{}}
	result.Inspection = (CardInspectionOptions{ExpectedGeneration: o.ExpectedGeneration, ObservedCard: true, CertificateResolver: o.CertificateResolver}).Inspect(ctx, input)
	rawCard, err := card.UnmarshalOptions{}.UnmarshalRawCardFile(input)
	if err != nil {
		result.Issues = append(result.Issues, CardDownloadValidationIssue{Scope: "structure", Code: "tlv_truncated_or_invalid"})
		return result, nil
	}
	result.RecordCount = len(rawCard.GetRecords())
	result.Observations = o.observeFiles(rawCard)
	for _, observation := range result.Observations {
		if observation.Status == "PHYSICAL_EXPECTED_NOT_FOUND" {
			result.PhysicalCompleteness = "EXPECTED_FILES_NOT_FOUND"
		}
	}
	if err := card.ValidateCompleteDownload(rawCard, o.ExpectedGeneration); err != nil {
		code := "required_data_missing_or_invalid"
		var structure *card.DownloadStructureError
		if errors.As(err, &structure) {
			code = structure.Reason
			if structure.Unsupported {
				result.StructuralStatus = StructureUnsupported
				result.AcquisitionStatus = AcquisitionFailed
			}
			if code == "required_signature_missing" {
				result.AuthenticityStatus = AuthenticityMissing
				result.Cryptography = "missing"
			}
		}
		for i := range result.Observations {
			if result.Observations[i].Status == "ACQUIRED" {
				result.Observations[i].Status = "PRESENT_UNCHECKED"
			}
		}
		result.Issues = append(result.Issues, CardDownloadValidationIssue{Scope: "structure", Code: code})
		return result, nil
	}
	result.AcquisitionStatus = AcquisitionComplete
	result.StructuralStatus = StructureValid
	result.StructuralValid = true
	raw, err := Unmarshal(input)
	if err == nil {
		parsed, parseErr := Parse(raw)
		result.SemanticValid = parseErr == nil && parsed.GetDriverCard() != nil
	}
	if !result.SemanticValid {
		result.Issues = append(result.Issues, CardDownloadValidationIssue{Scope: "analysis", Code: "semantic_decoder_unavailable"})
	}
	assessment := (card.AuthenticateOptions{CertificateResolver: o.CertificateResolver}).AssessAuthenticity(ctx, rawCard)
	result.AuthenticityStatus = AuthenticityStatus(assessment.Status)
	switch result.AuthenticityStatus {
	case AuthenticityVerified:
		result.Cryptography = "verified"
	case AuthenticityInvalid:
		result.Cryptography = "invalid"
	case AuthenticityMissing:
		result.Cryptography = "missing"
	}
	for _, issue := range assessment.Issues {
		result.Issues = append(result.Issues, CardDownloadValidationIssue{Scope: "authenticity", Code: issue.Reason, Application: issue.Application})
	}
	return result, nil
}

func (o CardDownloadValidationOptions) observeFiles(raw *cardv1.RawCardFile) []CardDownloadEFObservation {
	files := map[int]bool{}
	for _, r := range raw.GetRecords() {
		files[int(r.GetTag())] = true
	}
	var result []CardDownloadEFObservation
	add := func(fid, app int, requirement string, physicalExpected bool) {
		tag := fid<<8 | app
		status, reason := "ACQUIRED", ""
		if !files[tag] {
			switch {
			case requirement == "REQUIRED":
				status = "REQUIRED_ABSENT"
			case fid == 0x0540:
				status = "EXCLUDED_PROTECTED"
				reason = "outside_ordinary_acquisition_profile"
			case physicalExpected && o.ObservedCard:
				status = "PHYSICAL_EXPECTED_NOT_FOUND"
				reason = "observed_g2v2_expected_ef_not_found"
			default:
				status = "OPTIONAL_ABSENT"
			}
		}
		result = append(result, CardDownloadEFObservation{Tag: tag, Requirement: requirement, Status: status, Reason: reason})
	}
	add(2, 0, "OPTIONAL", false)
	add(5, 0, "OPTIONAL", false)
	for _, app := range []int{0, 2} {
		if app == 2 && o.ExpectedGeneration == "G1" {
			break
		}
		for _, fid := range append(card.RequiredDownloadData(app), card.RequiredDownloadCertificates(app, true)...) {
			add(fid, app, "REQUIRED", false)
		}
		if app == 2 {
			add(0xc100, 2, "IF_PRESENT", false)
			for _, fid := range []int{0x0525, 0x0526, 0x0527, 0x0528, 0x0529, 0x0530} {
				add(fid, 2, "IF_PRESENT", o.ExpectedGeneration == "G2V2")
			}
			add(0x0540, 2, "EXCLUDED_ORDINARY", false)
		}
		add(0x0507, app, "IF_PRESENT", false)
		add(0x0521, app, "IF_PRESENT", false)
	}
	return result
}
