package model

type RiskRule interface {
	Category() RiskCategory
	GenerateRisks() []Risk
	SupportedTags() []string
}
