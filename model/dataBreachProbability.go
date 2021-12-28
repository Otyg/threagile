package model

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type DataBreachProbability int

const (
	Improbable DataBreachProbability = iota
	Possible
	Probable
)

func DataBreachProbabilityValues() []core.TypeEnum {
	return []core.TypeEnum{
		Improbable,
		Possible,
		Probable,
	}
}

func ParseDataBreachProbability(value string) (result DataBreachProbability, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range DataBreachProbabilityValues() {
		if candidate.String() == value {
			return candidate.(DataBreachProbability), err
		}
	}
	return result, errors.New("Unable to parse into type: " + value)
}

func (what DataBreachProbability) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"improbable", "possible", "probable"}[what]
}

func (what DataBreachProbability) Title() string {
	return [...]string{"Improbable", "Possible", "Probable"}[what]
}

func (what DataBreachProbability) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}
