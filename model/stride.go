package model

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type STRIDE int

const (
	Spoofing STRIDE = iota
	Tampering
	Repudiation
	InformationDisclosure
	DenialOfService
	ElevationOfPrivilege
)

func STRIDEValues() []core.TypeEnum {
	return []core.TypeEnum{
		Spoofing,
		Tampering,
		Repudiation,
		InformationDisclosure,
		DenialOfService,
		ElevationOfPrivilege,
	}
}

func ParseStride(value string) (result STRIDE, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range STRIDEValues() {
		if candidate.String() == value {
			return candidate.(STRIDE), err
		}
	}
	return result, errors.New("Unable to parse into type: " + value)
}

func (what STRIDE) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service", "elevation-of-privilege"}[what]
}

func (what STRIDE) Title() string {
	return [...]string{"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}[what]
}

func (what STRIDE) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}
