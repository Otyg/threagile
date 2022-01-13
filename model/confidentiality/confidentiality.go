package confidentiality

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type Confidentiality int

const (
	Unknown Confidentiality = iota
	Public
	Internal
	Restricted
	Confidential
	StrictlyConfidential
)

func ConfidentialityValues() []core.TypeEnum {
	return []core.TypeEnum{
		Unknown,
		Public,
		Internal,
		Restricted,
		Confidential,
		StrictlyConfidential,
	}
}

func ParseConfidentiality(value string) (confidentiality Confidentiality, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range ConfidentialityValues() {
		if candidate.String() == value {
			return candidate.(Confidentiality), err
		}
	}
	return confidentiality, errors.New("Unable to parse into confidentiality: " + value)
}

func (what Confidentiality) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unknown", "public", "internal", "restricted", "confidential", "strictly-confidential"}[what]
}

func (what Confidentiality) AttackerAttractivenessForAsset() float64 {
	// fibonacci starting at 8
	return [...]float64{8, 13, 21, 34, 55, 89}[what]
}
func (what Confidentiality) AttackerAttractivenessForProcessedOrStoredData() float64 {
	// fibonacci starting at 5
	return [...]float64{5, 8, 13, 21, 34, 55}[what]
}
func (what Confidentiality) AttackerAttractivenessForInOutTransferredData() float64 {
	// fibonacci starting at 2
	return [...]float64{2, 3, 5, 8, 13, 21}[what]
}

func (what Confidentiality) RatingStringInScale() string {
	result := "(rated "
	if what == Public || what == Unknown {
		result += "1"
	}
	if what == Internal {
		result += "2"
	}
	if what == Restricted {
		result += "3"
	}
	if what == Confidential {
		result += "4"
	}
	if what == StrictlyConfidential {
		result += "5"
	}
	result += " in scale of 5)"
	return result
}
