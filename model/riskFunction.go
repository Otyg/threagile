package model

import "encoding/json"

type RiskFunction int

const (
	BusinessSide RiskFunction = iota
	Architecture
	Development
	Operations
)

func RiskFunctionValues() []TypeEnum {
	return []TypeEnum{
		BusinessSide,
		Architecture,
		Development,
		Operations,
	}
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
