package model

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type RiskFunction int

const (
	BusinessSide RiskFunction = iota
	Architecture
	Development
	Operations
)

func RiskFunctionValues() []core.TypeEnum {
	return []core.TypeEnum{
		BusinessSide,
		Architecture,
		Development,
		Operations,
	}
}

func ParseRiskFunction(value string) (result RiskFunction, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range RiskFunctionValues() {
		if candidate.String() == value {
			return candidate.(RiskFunction), err
		}
	}
	return result, errors.New("Unable to parse into type: " + value)
}

func (what RiskFunction) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"business-side", "architecture", "development", "operations"}[what]
}

func (what RiskFunction) Title() string {
	return [...]string{"Business Side", "Architecture", "Development", "Operations"}[what]
}

func (what RiskFunction) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}
