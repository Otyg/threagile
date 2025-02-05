package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type missingAuditOfSensitiveAsset string

var RiskRule missingAuditOfSensitiveAsset

func (r missingAuditOfSensitiveAsset) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "missing-audit-log-of-sensitive-asset",
		Title:                      "Missing Audit Log Of Sensitive Asset",
		Description:                "Access to sensitive assets must be monitored and logged. For confidential assets access should be logged and assets where integrity is important changes must be logged.",
		Impact:                     "Investigations and audits of access and/or changes to sensitive data will be harder",
		ASVS:                       "[v4.0.2-V7.1 - Log content](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x15-V7-Error-Logging.md#v71-log-content)",
		CheatSheet:                 "[Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)",
		Action:                     "Logging and monitoring",
		Mitigation:                 "Implement auditlogging for all sensitive assets",
		Check:                      "Are access to sensitive assets logged according to ASVS and cheat sheet?",
		Function:                   model.Development,
		STRIDE:                     model.Repudiation,
		DetectionLogic:             "Any asset with confidentiiality greater than internal or integrity greater or equal to operational",
		RiskAssessment:             "The risk rating depends on the sensitivity of the technical assets and data processed.",
		FalsePositives:             "None",
		ModelFailurePossibleReason: false,
		CWE:                        1009,
	}
}

func (r missingAuditOfSensitiveAsset) SupportedTags() []string {
	return []string{"PII"}
}

func (r missingAuditOfSensitiveAsset) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology == model.Monitoring {
			continue
		}
		impact := model.MediumImpact
		isSensitiveAsset := false
		if technicalAsset.Confidentiality >= confidentiality.Restricted || technicalAsset.Integrity >= criticality.Important || technicalAsset.IsTaggedWithAny(r.SupportedTags()...) {
			isSensitiveAsset = true
			if technicalAsset.Confidentiality == confidentiality.Confidential || technicalAsset.Integrity == criticality.Critical {
				impact = model.HighImpact
			} else if technicalAsset.Confidentiality == confidentiality.StrictlyConfidential || technicalAsset.Integrity == criticality.MissionCritical {
				impact = model.VeryHighImpact
			}
		}
		if !isSensitiveAsset {
			datas := append(technicalAsset.DataAssetsProcessedSorted(), technicalAsset.DataAssetsStoredSorted()...)
			for _, data := range datas {
				if data.Confidentiality >= confidentiality.Restricted || data.Integrity >= criticality.Important || data.IsTaggedWithAny(r.SupportedTags()...) {
					isSensitiveAsset = true
					if (data.Confidentiality == confidentiality.Confidential || data.Integrity == criticality.Critical) && impact < model.HighImpact {
						impact = model.HighImpact
					}
					if (data.Confidentiality == confidentiality.StrictlyConfidential || data.Integrity == criticality.MissionCritical) && impact <= model.VeryHighImpact {
						impact = model.VeryHighImpact
					}
				}
			}
		}

		if isSensitiveAsset {
			probability := model.VeryLikely
			commLinks := technicalAsset.CommunicationLinks
			for _, commLink := range commLinks {
				destination := model.ParsedModelRoot.TechnicalAssets[commLink.TargetId]
				if destination.Technology == model.Monitoring {
					probability = model.Unlikely
					break
				}
			}
			risks = append(risks, createRisk(technicalAsset, impact, probability))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, probability model.RiskExploitationLikelihood) model.Risk {
	title := "<b>Missing audit log</b> risk at <b>" + technicalAsset.Title + "</b>"
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
