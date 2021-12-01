package report

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/support"
)

/*type Risk struct {
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
}*/
type Finding struct {
	Title                 string `json:"title"`
	Description           string `json:"description"`
	Severity              string `json:"severity"`
	Mitigation            string `json:"mitigation"`
	CWE                   int    `json:"cwe"`
	Impact                string `json:"impact"`
	SeverityJustification string `json:"severity_justification"`
	References            string `json:"references"`
	StaticFinding         bool   `json:"static_finding"`
	DynamicFinding        bool   `json:"dynamic_finding"`
	UniqId                string `json:"unique_id_from_tool"`
	VulnId                string `json:"vuln_id_from_tool"`
	Component             string `json:"component_name"`
	Active                bool   `json:"active"`
	Verified              bool   `json:"verified"`
	FalsePositive         bool   `json:"false_p"`
	Mitigated             bool   `json:"is_mitigated"`
	RiskAccepted          bool   `json:"risk_accepted"`
	UnderDefectReview     bool   `json:"under_defect_review"`
	UnderReview           bool   `json:"under_review"`
}

func WriteDefectdojoGeneric(filename string) {
	findings := make([]Finding, 0)

	for _, category := range model.SortedRiskCategories() {
		risks := model.SortedRisksOfCategory(category)
		for _, risk := range risks {
			status := risk.GetRiskTrackingStatusDefaultingUnchecked().String()
			if !model.ParsedModelRoot.TechnicalAssets[risk.MostRelevantTechnicalAssetId].OutOfScope {
				var finding Finding
				switch risk.Severity.String() {
				case "low":
					finding.Severity = "Info"
				case "medium":
					finding.Severity = "Low"
				case "elevated":
					finding.Severity = "Medium"
				case "high":
					finding.Severity = "High"
				case "critical":
					finding.Severity = "Critical"
				}
				finding.StaticFinding = true
				finding.DynamicFinding = false
				finding.FalsePositive = false
				finding.Active = true
				finding.Mitigated = false
				finding.RiskAccepted = false
				finding.UnderDefectReview = false
				finding.UnderReview = false
				if status == "false-positive" {
					finding.FalsePositive = true
					finding.Active = false
				}

				if status == "mitigated" {
					finding.Mitigated = true
					finding.Active = false
					finding.Verified = true
				}

				if status == "accepted" {
					finding.RiskAccepted = true
					finding.Verified = true
				}

				if status == "in-discussion" {
					finding.UnderDefectReview = true
					finding.UnderReview = true
				}

				finding.CWE = risk.Category.CWE
				finding.Title = strings.Title(risk.Category.Function.String()) + ": " + strings.Title(strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(risk.Title), "<b>", ""), "</b>", ""))
				finding.Mitigation = risk.Category.Mitigation +
					"\nCheck: " + risk.Category.Check +
					"\nASVS: " + support.GetLinkText(risk.Category.ASVS) +
					"\nCheatSheet: " + support.GetLinkText(risk.Category.CheatSheet) +
					"\nTestingGuide: " + support.GetLinkText(risk.Category.TestingGuide)
				finding.Impact = risk.Category.Impact
				finding.SeverityJustification = risk.Category.RiskAssessment
				finding.Description = "STRIDE: " + strings.Title(risk.Category.STRIDE.String()) +
					"\n" + risk.Category.Description +
					"\nDetection logic: " + risk.Category.DetectionLogic +
					"\nFalse positives: " + risk.Category.FalsePositives
				finding.References = support.GetLinkUrl(risk.Category.ASVS) +
					"\n" + support.GetLinkUrl(risk.Category.CheatSheet) +
					"\n" + support.GetLinkUrl(risk.Category.TestingGuide)
				finding.UniqId = risk.SyntheticId
				finding.VulnId = risk.CategoryId
				finding.Component = strings.Title(risk.Category.Function.String())
				findings = append(findings, finding)
			}
		}
	}
	meh := make(map[string][]Finding)
	meh["findings"] = findings
	jsonBytes, err := json.Marshal(meh)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}

}
