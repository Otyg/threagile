package model

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type Quantity int

const (
	VeryFew Quantity = iota
	Few
	Many
	VeryMany
)

func QuantityValues() []core.TypeEnum {
	return []core.TypeEnum{
		VeryFew,
		Few,
		Many,
		VeryMany,
	}
}

func ParseQuantity(value string) (quantity Quantity, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range QuantityValues() {
		if candidate.String() == value {
			return candidate.(Quantity), err
		}
	}
	return quantity, errors.New("Unable to parse into type: " + value)
}

func (what Quantity) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"very-few", "few", "many", "very-many"}[what]
}

func (what Quantity) Title() string {
	return [...]string{"very few", "few", "many", "very many"}[what]
}

func (what Quantity) QuantityFactor() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5}[what]
}
