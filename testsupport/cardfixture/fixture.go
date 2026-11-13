// Package cardfixture exposes the existing synthetic PKI to integration tests
// in the containing application. Application code must never use test trust.
package cardfixture

import "github.com/way-platform/tachograph-go/internal/testcard"

type Fixture = testcard.Fixture

var New = testcard.New
