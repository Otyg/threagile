package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type uncheckedDeployment string

var RiskRule uncheckedDeployment

func (r uncheckedDeployment) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unchecked-deployment",
		Title: "Unchecked Deployment",
		Description: "For each build-pipeline component Unchecked Deployment risks might arise when the build-pipeline " +
			"does not include established DevSecOps best-practices. DevSecOps best-practices scan as part of CI/CD pipelines for " +
			"vulnerabilities in source- or byte-code, dependencies, container layers, and dynamically against running test systems. " +
			"There are several open-source and commercial tools existing in the categories DAST, SAST, and IAST.",
		Impact: "If this risk remains unmitigated, vulnerabilities in custom-developed software or their dependencies " +
			"might not be identified during continuous deployment cycles.",
		ASVS:       "[v.4.0.3-V14 - Configuration Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x22-V14-Config.md)",
		CheatSheet: "[Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Apply DevSecOps best-practices and use scanning tools to identify vulnerabilities in source- or byte-code," +
			"dependencies, container layers, and optionally also via dynamic scans against running test systems.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Architecture,
		STRIDE:         model.Tampering,
		DetectionLogic: "All development-relevant technical assets.",
		RiskAssessment: "The risk rating depends on the highest rating of the technical assets and data assets processed by deployment-receiving targets.",
		FalsePositives: "When the build-pipeline does not build any software components it can be considered a false positive " +
			"after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1127,
	}
}

func (r uncheckedDeployment) SupportedTags() []string {
	return []string{}
}

func (r uncheckedDeployment) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope && technicalAsset.Technology.IsDevelopmentRelevant() {
			risks = append(risks, createRisk(technicalAsset))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Unchecked Deployment</b> risk at <b>" + technicalAsset.Title + "</b>"
	// impact is depending on highest rating
	impact := model.LowImpact
	// data breach at all deployment targets
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, codeDeploymentTargetCommLink := range technicalAsset.CommunicationLinks {
		if codeDeploymentTargetCommLink.Usage == model.DevOps {
			for _, dataAssetID := range codeDeploymentTargetCommLink.DataAssetsSent {
				// it appears to be code when elevated integrity rating of sent data asset
				if model.ParsedModelRoot.DataAssets[dataAssetID].Integrity >= criticality.Important {
					// here we've got a deployment target which has its data assets at risk via deployment of backdoored code
					uniqueDataBreachTechnicalAssetIDs[codeDeploymentTargetCommLink.TargetId] = true
					targetTechAsset := model.ParsedModelRoot.TechnicalAssets[codeDeploymentTargetCommLink.TargetId]
					if targetTechAsset.HighestConfidentiality() >= confidentiality.Confidential ||
						targetTechAsset.HighestIntegrity() >= criticality.Critical ||
						targetTechAsset.HighestAvailability() >= criticality.Critical {
						impact = model.MediumImpact
					}
					break
				}
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key, _ := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	// create risk
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Possible,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
