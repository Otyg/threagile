package model

type RiskRule interface {
	Category() RiskCategory
	GenerateRisks() []Risk
	SupportedTags() []string
}

type CustomRiskRule interface {
	Category() RiskCategory
	SupportedTags() []string
	GenerateRisks() []Risk
}
