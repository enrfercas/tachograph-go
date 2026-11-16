package tachograph

import (
	"context"
	"github.com/way-platform/tachograph-go/internal/card"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
)

type CardFileInspection = card.DownloadInspection
type CardInspectionProfile = card.DownloadProfile
type CardInspectionDefect = card.InventoryDefect
type CardInspectionBlock = card.InspectionBlock
type CardTemporalEvidence = card.TemporalEvidence
type CardAuthenticationEvidence = card.AuthenticationEvidence

const CardAuthenticationPolicyVersion = card.AuthenticationPolicyVersion

func CheckCardInventory(raw *cardv1.RawCardFile) (CardInspectionProfile, []CardInspectionDefect) {
	p := card.ResolveDownloadProfile(raw, "", false)
	return p, card.InspectInventory(raw, p, nil)
}

type CardInspectionOptions struct {
	ExpectedGeneration  string
	ObservedCard        bool
	ObservedPresentTags []int
	CertificateResolver CertificateResolver
	TemporalEvidence    *CardTemporalEvidence
}

func (o CardInspectionOptions) Inspect(ctx context.Context, input []byte) *CardFileInspection {
	return (card.InspectionOptions{AuthenticateOptions: card.AuthenticateOptions{CertificateResolver: o.CertificateResolver, TemporalEvidence: o.TemporalEvidence}, ExpectedGeneration: o.ExpectedGeneration, ObservedCard: o.ObservedCard, ObservedPresentTags: o.ObservedPresentTags}).InspectDownload(ctx, input)
}
