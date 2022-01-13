package criticality

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type Criticality int

const (
	Unknown Criticality = iota
	Archive
	Operational
	Important
	Critical
	MissionCritical
)

func CriticalityValues() []core.TypeEnum {
	return []core.TypeEnum{
		Unknown,
		Archive,
		Operational,
		Important,
		Critical,
		MissionCritical,
	}
}

func ParseCriticality(value string) (criticality Criticality, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range CriticalityValues() {
		if candidate.String() == value {
			return candidate.(Criticality), err
		}
	}
	return criticality, errors.New("Unable to parse into criticality: " + value)
}

func (what Criticality) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unknown", "archive", "operational", "important", "critical", "mission-critical"}[what]
}

func (what Criticality) AttackerAttractivenessForAsset() float64 {
	// fibonacci starting at 5
	return [...]float64{5, 8, 13, 21, 34, 55}[what]
}
func (what Criticality) AttackerAttractivenessForProcessedOrStoredData() float64 {
	// fibonacci starting at 3
	return [...]float64{3, 5, 8, 13, 21, 34}[what]
}
func (what Criticality) AttackerAttractivenessForInOutTransferredData() float64 {
	// fibonacci starting at 2
	return [...]float64{2, 3, 5, 8, 13, 21}[what]
}

func (what Criticality) RatingStringInScale() string {
	result := "(rated "
	if what == Archive || what == Unknown {
		result += "1"
	}
	if what == Operational {
		result += "2"
	}
	if what == Important {
		result += "3"
	}
	if what == Critical {
		result += "4"
	}
	if what == MissionCritical {
		result += "5"
	}
	result += " in scale of 5)"
	return result
}
