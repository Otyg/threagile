package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type missingBuildInfrastructure string

var RiskRule missingBuildInfrastructure

func (r missingBuildInfrastructure) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-build-infrastructure",
		Title: "Missing Build Infrastructure",
		Description: "The modeled architecture does not contain a build infrastructure (devops-client, sourcecode-repo, build-pipeline, etc.), " +
			"which might be the risk of a model missing critical assets (and thus not seeing their risks). " +
			"If the architecture contains custom-developed parts, the pipeline where code gets developed " +
			"and built needs to be part of the model.",
		Impact: "If this risk is unmitigated, attackers might be able to exploit risks unseen in this threat model due to " +
			"critical build infrastructure components missing in the model.",
		ASVS:       "[v4.0.3-V1 - Architecture, Design and Threat Modeling Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x10-V1-Architecture.md)",
		CheatSheet: "[Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Include the build infrastructure in the model.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Architecture,
		STRIDE:     model.Tampering,
		DetectionLogic: "Models with in-scope custom-developed parts missing in-scope development (code creation) and build infrastructure " +
			"components (devops-client, sourcecode-repo, build-pipeline, etc.).",
		RiskAssessment: "The risk rating depends on the highest sensitivity of the in-scope assets running custom-developed parts.",
		FalsePositives: "Models not having any custom-developed parts " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        1127,
	}
}

func (r missingBuildInfrastructure) SupportedTags() []string {
	return []string{}
}

func (r missingBuildInfrastructure) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	hasCustomDevelopedParts, hasBuildPipeline, hasSourcecodeRepo, hasDevOpsClient := false, false, false, false
	impact := model.LowImpact
	var mostRelevantAsset model.TechnicalAsset
	for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.CustomDevelopedParts && !technicalAsset.OutOfScope {
			hasCustomDevelopedParts = true
			if impact == model.LowImpact {
				mostRelevantAsset = technicalAsset
				if technicalAsset.HighestConfidentiality() >= confidentiality.Confidential ||
					technicalAsset.HighestIntegrity() >= criticality.Critical ||
					technicalAsset.HighestAvailability() >= criticality.Critical {
					impact = model.MediumImpact
				}
			}
			if technicalAsset.Confidentiality >= confidentiality.Confidential ||
				technicalAsset.Integrity >= criticality.Critical ||
				technicalAsset.Availability >= criticality.Critical {
				impact = model.MediumImpact
			}
			// just for referencing the most interesting asset
			if technicalAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
				mostRelevantAsset = technicalAsset
			}
		}
		if technicalAsset.Technology == model.BuildPipeline {
			hasBuildPipeline = true
		}
		if technicalAsset.Technology == model.SourcecodeRepository {
			hasSourcecodeRepo = true
		}
		if technicalAsset.Technology == model.DevOpsClient {
			hasDevOpsClient = true
		}
	}
	hasBuildInfrastructure := hasBuildPipeline && hasSourcecodeRepo && hasDevOpsClient
	if hasCustomDevelopedParts && !hasBuildInfrastructure {
		risks = append(risks, createRisk(mostRelevantAsset, impact))
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}