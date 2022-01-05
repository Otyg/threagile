package model

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type TechnicalAssetMachine int

const (
	Physical TechnicalAssetMachine = iota
	Virtual
	Container
	Serverless
)

func TechnicalAssetMachineValues() []core.TypeEnum {
	return []core.TypeEnum{
		Physical,
		Virtual,
		Container,
		Serverless,
	}
}

func (what TechnicalAssetMachine) String() string {
	return [...]string{"physical", "virtual", "container", "serverless"}[what]
}

func ParseTechnicalAssetMachine(value string) (technicalAssetMachine TechnicalAssetMachine, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range TechnicalAssetMachineValues() {
		if candidate.String() == value {
			return candidate.(TechnicalAssetMachine), err
		}
	}
	return technicalAssetMachine, errors.New("Unable to parse into type: " + value)
}
