package model

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type TechnicalAssetType int

const (
	ExternalEntity TechnicalAssetType = iota
	Process
	Datastore
)

func TechnicalAssetTypeValues() []core.TypeEnum {
	return []core.TypeEnum{
		ExternalEntity,
		Process,
		Datastore,
	}
}

func (what TechnicalAssetType) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"external-entity", "process", "datastore"}[what]
}

func ParseTechnicalAssetType(value string) (technicalAssetType TechnicalAssetType, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range TechnicalAssetTypeValues() {
		if candidate.String() == value {
			return candidate.(TechnicalAssetType), err
		}
	}
	return technicalAssetType, errors.New("Unable to parse into type: " + value)
}
