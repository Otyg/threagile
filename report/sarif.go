package report

import (
	"strconv"
	"strings"

	"github.com/otyg/threagile/model"
	"github.com/owenrumney/go-sarif/sarif"
)

func WriteOpenSarif(filename string) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		panic(err)
	}
	run := sarif.NewRun("Threagile", "https://threagile.io/")
	for _, category := range model.SortedRiskCategories() {
		var description sarif.MultiformatMessageString
		description.Text = category.Description +
			"\nSTRIDE: " + strings.Title(category.STRIDE.String()) +
			"\nCheck: " + category.Check +
			"\nASVS: " + category.ASVS +
			"\nCheatSheet: " + category.CheatSheet +
			"\nTestingGuide: " + category.TestingGuide +
			"\nMitigation: " + category.Mitigation +
			"\nDetection logic: " + category.DetectionLogic +
			"\nFalse positives: " + category.FalsePositives +
			"\nCWE: " + strconv.Itoa(category.CWE)
		run.AddRule(category.Id).WithFullDescription(&description).WithName(category.Title)
	}
	for _, risk := range model.AllRisks() {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() != model.FalsePositive && risk.GetRiskTrackingStatusDefaultingUnchecked() != model.Mitigated {
			var location = sarif.NewLocation()
			if risk.MostRelevantTechnicalAssetId != "" {
				techAsset := model.ParsedModelRoot.TechnicalAssets[risk.MostRelevantTechnicalAssetId]
				location.WithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(
							sarif.NewArtifactLocation().WithUri("TechnicalAsset:" + techAsset.Id)).
						WithAddress(
							sarif.NewAddress().WithFullyQualifiedName(techAsset.Id).WithName(techAsset.Title)))
			}
			var rule, err = run.GetRuleById(risk.CategoryId)
			if err != nil {
				panic(err)
			}
			run.AddResult(risk.SyntheticId).
				WithLevel(getLevel(risk.Severity)).
				WithRule(sarif.NewReportingDescriptorReference().WithId(risk.CategoryId)).
				WithMessage(
					sarif.NewTextMessage(
						strings.Title(risk.Category.Function.String()) + ": " + strings.Title(strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(risk.Title), "<b>", ""), "</b>", "")) +
							"\n\n" + rule.FullDescription.Text)).
				WithLocation(location)
		}
	}

	report.AddRun(run)
	if err := report.WriteFile(filename); err != nil {
		panic(err)
	}
}

func getLevel(severity model.RiskSeverity) string {
	var level = "warning"
	switch severity {
	case model.LowSeverity:
		level = "note"
	case model.CriticalSeverity:
		level = "error"
	}
	return level
}
