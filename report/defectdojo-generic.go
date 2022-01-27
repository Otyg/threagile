package report

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/support"
)

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
				"\nCRE: " + risk.Category.CRE +
				"\nASVS: " + risk.Category.ASVS +
				"\nCheatSheet: " + risk.Category.CheatSheet +
				"\nTestingGuide: " + risk.Category.TestingGuide
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
