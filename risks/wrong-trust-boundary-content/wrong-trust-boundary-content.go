package main

import (
	"github.com/otyg/threagile/model"
)

type wrongTrustBoundaryContent string

var RiskRule wrongTrustBoundaryContent

func (r wrongTrustBoundaryContent) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "wrong-trust-boundary-content",
		Title: "Wrong Trust Boundary Content",
		Description: "When a trust boundary of type " + model.NetworkPolicyNamespaceIsolation.String() + " contains " +
			"non-container assets it is likely to be a model failure.",
		Impact:                     "If this potential model error is not fixed, some risks might not be visible.",
		ASVS:                       "[v4.0.3-V1 - Architecture, Design and Threat Modeling Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x10-V1-Architecture.md)",
		CheatSheet:                 "[Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)",
		Action:                     "Model Consistency",
		Mitigation:                 "Try to model the correct types of trust boundaries and data assets.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Architecture,
		STRIDE:                     model.ElevationOfPrivilege,
		DetectionLogic:             "Trust boundaries which should only contain containers, but have different assets inside.",
		RiskAssessment:             model.LowSeverity.String(),
		FalsePositives:             "Usually no false positives as this looks like an incomplete model.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func (r wrongTrustBoundaryContent) SupportedTags() []string {
	return []string{}
}

func (r wrongTrustBoundaryContent) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, trustBoundary := range model.ParsedModelRoot.TrustBoundaries {
		if trustBoundary.Type == model.NetworkPolicyNamespaceIsolation {
			for _, techAssetID := range trustBoundary.TechnicalAssetsInside {
				techAsset := model.ParsedModelRoot.TechnicalAssets[techAssetID]
				if techAsset.Machine != model.Container && techAsset.Machine != model.Serverless {
					risks = append(risks, createRisk(techAsset))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Wrong Trust Boundary Content</b> (non-container asset inside container trust boundary) at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, model.LowImpact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           model.LowImpact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
