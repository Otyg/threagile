package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type accidentalSecretLeakRule string

var RiskRule accidentalSecretLeakRule

func (r accidentalSecretLeakRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "accidental-secret-leak",
		Title: "Accidental Secret Leak",
		Description: "Sourcecode repositories (including their histories) as well as artifact registries can accidentally contain secrets like " +
			"checked-in or packaged-in passwords, API tokens, certificates, crypto keys, etc.",
		Impact: "If this risk is unmitigated, attackers which have access to affected sourcecode repositories or artifact registries might " +
			"find secrets accidentally checked-in.",
		CRE:        "[253-452: Securely automate build and deployment in pipeline](https://www.opencre.org/cre/253-452)",
		ASVS:       "[v4.0.3-V14 - Configuration Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x22-V14-Config.md)",
		CheatSheet: "[Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Establish measures preventing accidental check-in or package-in of secrets into sourcecode repositories " +
			"and artifact registries. This starts by using good .gitignore and .dockerignore files, but does not stop there. " +
			"See for example tools like <i>\"git-secrets\" or \"Talisman\"</i> to have check-in preventive measures for secrets. " +
			"Consider also to regularly scan your repositories for secrets accidentally checked-in using scanning tools like <i>\"gitleaks\" or \"gitrob\"</i>.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Operations,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "In-scope sourcecode repositories and artifact registries.",
		RiskAssessment:             "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed and stored.",
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (r accidentalSecretLeakRule) SupportedTags() []string {
	return []string{"git", "nexus"}
}

func (r accidentalSecretLeakRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !techAsset.OutOfScope &&
			(techAsset.Technology == model.SourcecodeRepository || techAsset.Technology == model.ArtifactRegistry) {
			var risk model.Risk
			if techAsset.IsTaggedWithAny("git") {
				risk = createRisk(techAsset, "Git", "Git Leak Prevention")
			} else {
				risk = createRisk(techAsset, "", "")
			}
			risks = append(risks, risk)
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, prefix, details string) model.Risk {
	if len(prefix) > 0 {
		prefix = " (" + prefix + ")"
	}
	title := "<b>Accidental Secret Leak" + prefix + "</b> risk at <b>" + technicalAsset.Title + "</b>"
	if len(details) > 0 {
		title += ": <u>" + details + "</u>"
	}
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() >= confidentiality.Confidential ||
		technicalAsset.HighestIntegrity() >= criticality.Critical ||
		technicalAsset.HighestAvailability() >= criticality.Critical {
		impact = model.MediumImpact
	}
	if technicalAsset.HighestConfidentiality() == confidentiality.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == criticality.MissionCritical ||
		technicalAsset.HighestAvailability() == criticality.MissionCritical {
		impact = model.HighImpact
	}
	// create risk
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
