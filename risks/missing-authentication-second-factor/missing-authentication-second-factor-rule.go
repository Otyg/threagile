package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type missingAuthenticationSecondFactor string

var RiskRule missingAuthenticationSecondFactor

func (r missingAuthenticationSecondFactor) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-authentication-second-factor",
		Title: "Missing Two-Factor Authentication (2FA)",
		Description: "Technical assets (especially multi-tenant systems) should authenticate incoming requests with " +
			"two-factor (2FA) authentication when the asset processes or stores highly sensitive data (in terms of confidentiality, integrity, and availability) and is accessed by humans.",
		Impact:       "If this risk is unmitigated, attackers might be able to access or modify highly sensitive data without strong authentication.",
		ASVS:         "[v4.0.3-V2 - Authentication Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x11-V2-Authentication.md)",
		CheatSheet:   "[Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)",
		TestingGuide: "[v4.2-4.4 - Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing)",
		Action:       "Authentication with Second Factor (2FA)",
		Mitigation: "Apply an authentication method to the technical asset protecting highly sensitive data via " +
			"two-factor authentication for human users.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.BusinessSide,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets (except " + model.LoadBalancer.String() + ", " + model.ReverseProxy.String() + ", " + model.WAF.String() + ", " + model.IDS.String() + ", and " + model.IPS.String() + ") should authenticate incoming requests via two-factor authentication (2FA) " +
			"when the asset processes or stores highly sensitive data (in terms of confidentiality, integrity, and availability) and is accessed by a client used by a human user.",
		RiskAssessment: model.MediumSeverity.String(),
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        308,
	}
}

func (r missingAuthenticationSecondFactor) SupportedTags() []string {
	return []string{}
}

func (r missingAuthenticationSecondFactor) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope ||
			technicalAsset.Technology.IsTrafficForwarding() ||
			technicalAsset.Technology.IsUnprotectedCommsTolerated() {
			continue
		}
		if technicalAsset.HighestConfidentiality() >= confidentiality.Confidential ||
			technicalAsset.HighestIntegrity() >= criticality.Critical ||
			technicalAsset.HighestAvailability() >= criticality.Critical ||
			technicalAsset.MultiTenant {
			// check each incoming data flow
			commLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, commLink := range commLinks {
				caller := model.ParsedModelRoot.TechnicalAssets[commLink.SourceId]
				if caller.Technology.IsUnprotectedCommsTolerated() || caller.Type == model.Datastore {
					continue
				}
				if caller.UsedAsClientByHuman {
					moreRisky := commLink.HighestConfidentiality() >= confidentiality.Confidential ||
						commLink.HighestIntegrity() >= criticality.Critical
					if moreRisky && commLink.Authentication != model.TwoFactor {
						risks = append(risks, createRisk(technicalAsset, commLink, commLink, "", model.MediumImpact, model.Unlikely, true, RiskRule.Category()))
					}
				} else if caller.Technology.IsTrafficForwarding() {
					// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
					callersCommLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[caller.Id]
					for _, callersCommLink := range callersCommLinks {
						callersCaller := model.ParsedModelRoot.TechnicalAssets[callersCommLink.SourceId]
						if callersCaller.Technology.IsUnprotectedCommsTolerated() || callersCaller.Type == model.Datastore {
							continue
						}
						if callersCaller.UsedAsClientByHuman {
							moreRisky := callersCommLink.HighestConfidentiality() >= confidentiality.Confidential ||
								callersCommLink.HighestIntegrity() >= criticality.Critical
							if moreRisky && callersCommLink.Authentication != model.TwoFactor {
								risks = append(risks, createRisk(technicalAsset, commLink, callersCommLink, caller.Title, model.MediumImpact, model.Unlikely, true, RiskRule.Category()))
							}
						}
					}
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingAccess, incomingAccessOrigin model.CommunicationLink, hopBetween string,
	impact model.RiskExploitationImpact, likelihood model.RiskExploitationLikelihood, twoFactor bool, category model.RiskCategory) model.Risk {
	factorString := ""
	if twoFactor {
		factorString = "Two-Factor "
	}
	if len(hopBetween) > 0 {
		hopBetween = "forwarded via <b>" + hopBetween + "</b> "
	}
	risk := model.Risk{
		Category:               category,
		Severity:               model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing " + factorString + "Authentication</b> covering communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + model.ParsedModelRoot.TechnicalAssets[incomingAccessOrigin.SourceId].Title + "</b> " + hopBetween +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + incomingAccess.Id + "@" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
