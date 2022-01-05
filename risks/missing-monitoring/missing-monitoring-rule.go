package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type missingMonitoring string

var RiskRule missingMonitoring

func (r missingMonitoring) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "missing-monitoring",
		Title:                      "Missing Monitoring",
		Description:                "The model is missing a monitoring target for collecting, analysis and alerting on logdata and events.",
		Impact:                     "Without an external platform for monitoring an attacker might go undetected and might be able to tamper with logfiles etc.",
		ASVS:                       "[v4.0.3-7 - Error Handling and Logging Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x15-V7-Error-Logging.md)",
		CheatSheet:                 "",
		Action:                     "Logging and monitoring",
		Mitigation:                 "Send logdata and other events to an external platform for storage and analysis.",
		Check:                      "Are relevant logs sent to an external monitoring platform?",
		Function:                   model.Architecture,
		STRIDE:                     model.Repudiation,
		DetectionLogic:             "Models without a Monitoring platform",
		RiskAssessment:             "The risk rating depends on the sensitivity of the technical assets and data processed.",
		FalsePositives:             "None",
		ModelFailurePossibleReason: true,
		CWE:                        778,
	}
}

func (r missingMonitoring) SupportedTags() []string {
	return []string{}
}

func (r missingMonitoring) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	hasMonitoring := false
	var mostRelevantAsset model.TechnicalAsset
	impact := model.MediumImpact
	probability := model.Likely
	for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if techAsset.Technology == model.Monitoring {
			hasMonitoring = true
			break
		}
		if techAsset.HighestConfidentiality() == confidentiality.Confidential ||
			techAsset.HighestIntegrity() == criticality.Critical ||
			techAsset.HighestAvailability() == criticality.Critical {
			impact = model.HighImpact
			probability = model.VeryLikely
		} else if techAsset.HighestConfidentiality() == confidentiality.StrictlyConfidential ||
			techAsset.HighestIntegrity() == criticality.MissionCritical ||
			techAsset.HighestAvailability() == criticality.MissionCritical {
			impact = model.VeryHighImpact
			probability = model.VeryLikely
		}
		if techAsset.Confidentiality == confidentiality.Confidential ||
			techAsset.Integrity == criticality.Critical ||
			techAsset.Availability == criticality.Critical {
			impact = model.HighImpact
			probability = model.VeryLikely
		} else if techAsset.Confidentiality == confidentiality.StrictlyConfidential ||
			techAsset.Integrity == criticality.MissionCritical ||
			techAsset.Availability == criticality.MissionCritical {
			impact = model.VeryHighImpact
			probability = model.VeryLikely
		}
		// just for referencing the most interesting asset
		if techAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
			mostRelevantAsset = techAsset
		}
	}
	if !hasMonitoring {
		risks = append(risks, createRisk(mostRelevantAsset, impact, probability))
	} else {
		for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
			techAsset := model.ParsedModelRoot.TechnicalAssets[id]
			if techAsset.OutOfScope || techAsset.Technology == model.Monitoring {
				continue
			}
			targetMonitor := false
			impact := model.MediumImpact
			probability := model.Likely
			if techAsset.Confidentiality == confidentiality.Confidential ||
				techAsset.Integrity == criticality.Critical ||
				techAsset.Availability == criticality.Critical {
				impact = model.HighImpact
				probability = model.VeryLikely
			} else if techAsset.Confidentiality == confidentiality.StrictlyConfidential ||
				techAsset.Integrity == criticality.MissionCritical ||
				techAsset.Availability == criticality.MissionCritical {
				impact = model.VeryHighImpact
				probability = model.VeryLikely
			}
			commLinks := techAsset.CommunicationLinks
			for _, commLink := range commLinks {
				destination := model.ParsedModelRoot.TechnicalAssets[commLink.TargetId]
				if destination.Technology == model.Monitoring {
					targetMonitor = true
				}
			}
			if !targetMonitor {
				risks = append(risks, createRisk(techAsset, impact, probability))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, probability model.RiskExploitationLikelihood) model.Risk {
	title := "<b>Missing Monitoring (Logging platform)</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(probability, impact),
		ExploitationLikelihood:       probability,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
