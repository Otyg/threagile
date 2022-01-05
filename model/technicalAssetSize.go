package model

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type TechnicalAssetSize int

const (
	System TechnicalAssetSize = iota
	Service
	Application
	Component
)

func TechnicalAssetSizeValues() []core.TypeEnum {
	return []core.TypeEnum{
		System,
		Service,
		Application,
		Component,
	}
}

func (what TechnicalAssetSize) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"system", "service", "application", "component"}[what]
}

func ParseTechnicalAssetSize(value string) (technicalAssetSize TechnicalAssetSize, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range TechnicalAssetSizeValues() {
		if candidate.String() == value {
			return candidate.(TechnicalAssetSize), err
		}
	}
	return technicalAssetSize, errors.New("Unable to parse into size: " + value)
}
