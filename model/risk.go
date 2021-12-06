package model

type Risk struct {
	Category                        RiskCategory               `json:"-"`           // just for navigational convenience... not JSON marshalled
	CategoryId                      string                     `json:"category"`    // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	RiskStatus                      RiskStatus                 `json:"risk_status"` // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	Severity                        RiskSeverity               `json:"severity"`
	ExploitationLikelihood          RiskExploitationLikelihood `json:"exploitation_likelihood"`
	ExploitationImpact              RiskExploitationImpact     `json:"exploitation_impact"`
	Title                           string                     `json:"title"`
	SyntheticId                     string                     `json:"synthetic_id"`
	MostRelevantDataAssetId         string                     `json:"most_relevant_data_asset"`
	MostRelevantTechnicalAssetId    string                     `json:"most_relevant_technical_asset"`
	MostRelevantTrustBoundaryId     string                     `json:"most_relevant_trust_boundary"`
	MostRelevantSharedRuntimeId     string                     `json:"most_relevant_shared_runtime"`
	MostRelevantCommunicationLinkId string                     `json:"most_relevant_communication_link"`
	DataBreachProbability           DataBreachProbability      `json:"data_breach_probability"`
	DataBreachTechnicalAssetIDs     []string                   `json:"data_breach_technical_assets"`
	// TODO: refactor all "Id" here to "ID"?
}

type InputRiskIdentified struct {
	Severity                         string   `json:"severity"`
	Exploitation_likelihood          string   `json:"exploitation_likelihood"`
	Exploitation_impact              string   `json:"exploitation_impact"`
	Data_breach_probability          string   `json:"data_breach_probability"`
	Data_breach_technical_assets     []string `json:"data_breach_technical_assets"`
	Most_relevant_data_asset         string   `json:"most_relevant_data_asset"`
	Most_relevant_technical_asset    string   `json:"most_relevant_technical_asset"`
	Most_relevant_communication_link string   `json:"most_relevant_communication_link"`
	Most_relevant_trust_boundary     string   `json:"most_relevant_trust_boundary"`
	Most_relevant_shared_runtime     string   `json:"most_relevant_shared_runtime"`
}

func (what Risk) GetRiskTracking() RiskTracking { // TODO: Unify function naming reagrding Get etc.
	var result RiskTracking
	if riskTracking, ok := ParsedModelRoot.RiskTracking[what.SyntheticId]; ok {
		result = riskTracking
	}
	return result
}

func (what Risk) GetRiskTrackingStatusDefaultingUnchecked() RiskStatus {
	if riskTracking, ok := ParsedModelRoot.RiskTracking[what.SyntheticId]; ok {
		return riskTracking.Status
	}
	return Unchecked
}

func (what Risk) IsRiskTracked() bool {
	if _, ok := ParsedModelRoot.RiskTracking[what.SyntheticId]; ok {
		return true
	}
	return false
}
