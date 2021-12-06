package model

import "encoding/json"

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
