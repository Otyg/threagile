package model

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type Usage int

const (
	Business Usage = iota
	DevOps
)

func UsageValues() []core.TypeEnum {
	return []core.TypeEnum{
		Business,
		DevOps,
	}
}

func ParseUsage(value string) (usage Usage, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range UsageValues() {
		if candidate.String() == value {
			return candidate.(Usage), err
		}
	}
	return usage, errors.New("Unable to parse into type: " + value)
}

func (what Usage) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"business", "devops"}[what]
}

func (what Usage) Title() string {
	return [...]string{"Business", "DevOps"}[what]
}
