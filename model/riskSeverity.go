package model

import (
	"encoding/json"
	"errors"
	"strings"
)

type RiskSeverity int

const (
	LowSeverity RiskSeverity = iota
	MediumSeverity
	ElevatedSeverity
	HighSeverity
	CriticalSeverity
)

func RiskSeverityValues() []TypeEnum {
	return []TypeEnum{
		LowSeverity,
		MediumSeverity,
		ElevatedSeverity,
		HighSeverity,
		CriticalSeverity,
	}
}

func ParseRiskSeverity(value string) (result RiskSeverity, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range RiskSeverityValues() {
		if candidate.String() == value {
			return candidate.(RiskSeverity), err
		}
	}
	return result, errors.New("Unable to parse into type: " + value)
}

func (what RiskSeverity) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"low", "medium", "elevated", "high", "critical"}[what]
}

func (what RiskSeverity) Title() string {
	return [...]string{"Low", "Medium", "Elevated", "High", "Critical"}[what]
}

func (what RiskSeverity) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func CalculateSeverity(likelihood RiskExploitationLikelihood, impact RiskExploitationImpact) RiskSeverity {
	result := likelihood.Weight() * impact.Weight()
	if result <= 1 {
		return LowSeverity
	}
	if result <= 3 {
		return MediumSeverity
	}
	if result <= 8 {
		return ElevatedSeverity
	}
	if result <= 12 {
		return HighSeverity
	}
	return CriticalSeverity
}
func HighestSeverity(risks []Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result {
			result = risk.Severity
		}
	}
	return result
}

func HighestSeverityStillAtRisk(risks []Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result && risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
			result = risk.Severity
		}
	}
	return result
}
