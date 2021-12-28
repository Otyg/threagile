package model

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type RiskStatus int

const (
	Unchecked RiskStatus = iota
	InDiscussion
	Accepted
	InProgress
	Mitigated
	FalsePositive
)

func RiskStatusValues() []core.TypeEnum {
	return []core.TypeEnum{
		Unchecked,
		InDiscussion,
		Accepted,
		InProgress,
		Mitigated,
		FalsePositive,
	}
}

func ParseRiskStatus(value string) (result RiskStatus, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range RiskStatusValues() {
		if candidate.String() == value {
			return candidate.(RiskStatus), err
		}
	}
	return result, errors.New("Unable to parse into type: " + value)
}

func (what RiskStatus) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unchecked", "in-discussion", "accepted", "in-progress", "mitigated", "false-positive"}[what]
}

func (what RiskStatus) Title() string {
	return [...]string{"Unchecked", "in Discussion", "Accepted", "in Progress", "Mitigated", "False Positive"}[what]
}

func (what RiskStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what RiskStatus) IsStillAtRisk() bool {
	return what == Unchecked || what == InDiscussion || what == Accepted || what == InProgress
}
