package card

import (
	"fmt"
	"strings"

	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
)

// RequiredDownloadData is the shared DRIVER minimum of Appendix 7 DDP_035.
// A downloaded G1 application never proves physical G1 (MIG_011/MIG_012).
func RequiredDownloadData(application int) []int {
	result := []int{0x0501, 0x0520, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0508, 0x0522}
	if application == 2 {
		result = append(result, 0x0523, 0x0524)
	}
	return result
}

func RequiredDownloadCertificates(application int, requireLink bool) []int {
	if application == 0 {
		return []int{0xc100, 0xc108}
	}
	result := []int{0xc101, 0xc108}
	if requireLink {
		result = append(result, 0xc109)
	}
	return result
}

type DownloadProfile struct {
	Name               string   `json:"name"`
	Generation         string   `json:"generation"`
	PhysicalGeneration string   `json:"physicalGeneration"`
	Determined         bool     `json:"determined"`
	RequireLink        bool     `json:"requireLink"`
	Uncertainties      []string `json:"uncertainties,omitempty"`
}

type InventoryDefect struct {
	Name        string `json:"name,omitempty"`
	Code        string `json:"code"`
	Scope       string `json:"scope"`
	Application string `json:"application,omitempty"`
	FID         int    `json:"fid,omitempty"`
	Tag         int    `json:"tag,omitempty"`
	Offset      *int   `json:"offset,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

func (d InventoryDefect) Error() string { return fmt.Sprintf("%s (tag %06x)", d.Code, d.Tag) }

func ApplicationName(appendix int) string {
	if appendix&2 != 0 {
		return "Tachograph_G2"
	}
	return "Tachograph"
}

func EFName(tag int) string {
	g := ddv1.Generation_GENERATION_1
	if tag&2 != 0 {
		g = ddv1.Generation_GENERATION_2
	}
	f, ok := mapFidToElementaryFileType(uint16(tag>>8), g)
	if !ok {
		return fmt.Sprintf("EF_%04X", tag>>8)
	}
	words := strings.Split(strings.ToLower(strings.TrimPrefix(f.String(), "EF_")), "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, "_")
}

// ResolveDownloadProfile uses application identity or explicit acquisition
// evidence, never a certificate FID, filename, GNSS or date guessed from data.
func ResolveDownloadProfile(raw *cardv1.RawCardFile, expected string, observed bool) DownloadProfile {
	p := DownloadProfile{Name: "UNDETERMINED", Generation: "UNKNOWN", PhysicalGeneration: "UNKNOWN"}
	if observed && (expected == "G1" || expected == "G2V1" || expected == "G2V2") {
		p = DownloadProfile{Name: "APPENDIX_7_DRIVER_" + expected, Generation: expected, PhysicalGeneration: expected, Determined: true, RequireLink: expected != "G1"}
		return p
	}
	seen := map[int]bool{}
	for _, r := range raw.GetRecords() {
		tag := int(r.GetTag())
		if tag != 0x050100 && tag != 0x050102 {
			continue
		}
		if seen[tag] {
			return p
		}
		seen[tag] = true
		b := r.GetValue()
		if tag == 0x050102 {
			if len(b) != 17 || b[0] != 1 || b[1] != 1 || b[2] > 1 {
				return DownloadProfile{Name: "UNDETERMINED", Generation: "UNKNOWN", PhysicalGeneration: "UNKNOWN"}
			}
			p.Generation = "G2V1"
			if b[2] == 1 {
				p.Generation = "G2V2"
			}
		} else if len(b) != 10 || b[0] != 1 || b[1] != 0 || b[2] != 0 {
			return DownloadProfile{Name: "UNDETERMINED", Generation: "UNKNOWN", PhysicalGeneration: "UNKNOWN"}
		}
	}
	if p.Generation == "UNKNOWN" && seen[0x050100] {
		p.Generation = "G1"
	}
	if p.Generation != "UNKNOWN" {
		p.Determined = true
		p.Name = "APPENDIX_7_DRIVER_" + p.Generation
		p.RequireLink = p.Generation == "G2V2"
		if p.Generation == "G1" {
			p.Uncertainties = append(p.Uncertainties, "physical_generation_unknown_g1_compatible_download")
		}
		if p.Generation == "G2V1" {
			p.Uncertainties = append(p.Uncertainties, "historical_link_requirement_undetermined")
		}
	}
	return p
}

// InspectInventory is independent of certificate availability and accumulates
// all provable missing DATA and SIGNATURE obligations. presentTags must be
// positive acquisition evidence, not expectations inferred from a card version.
func InspectInventory(raw *cardv1.RawCardFile, p DownloadProfile, presentTags []int) []InventoryDefect {
	files := map[int]bool{}
	for _, r := range raw.GetRecords() {
		files[int(r.GetTag())] = true
	}
	defects := []InventoryDefect{}
	missing := func(tag int, code string) {
		defects = append(defects, InventoryDefect{Name: EFName(tag), Code: code, Scope: "inventory", Application: ApplicationName(tag & 255), FID: tag >> 8, Tag: tag})
	}
	if p.Determined {
		for _, app := range []int{0, 2} {
			if app == 2 && p.Generation == "G1" {
				break
			}
			for _, fid := range append(RequiredDownloadData(app), RequiredDownloadCertificates(app, p.RequireLink)...) {
				tag := fid<<8 | app
				if !files[tag] {
					missing(tag, "required_ef_missing")
				}
			}
		}
		for _, tag := range presentTags {
			fid := tag >> 8
			if tag&255 == 2 && (fid >= 0x0525 && fid <= 0x0529 || fid == 0x0530) && !files[tag] {
				missing(tag, "observed_required_ef_missing")
			}
		}
	}
	for _, r := range raw.GetRecords() {
		tag := int(r.GetTag())
		if !p.Determined || tag&1 != 0 || !isSignedEF(r.GetFile()) || r.GetFile() == cardv1.ElementaryFileType_ELEMENTARY_FILE_UNSPECIFIED {
			continue
		}
		if !files[tag+1] {
			missing(tag, "required_signature_missing")
		}
	}
	return defects
}
