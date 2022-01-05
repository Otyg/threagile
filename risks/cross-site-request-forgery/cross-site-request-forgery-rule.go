package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/criticality"
)

type crossSiteRequestForgeryRule string

var RiskRule crossSiteRequestForgeryRule

func (r crossSiteRequestForgeryRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "cross-site-request-forgery",
		Title:       "Cross-Site Request Forgery (CSRF)",
		Description: "When a web application is accessed via web protocols Cross-Site Request Forgery (CSRF) risks might arise.",
		Impact: "If this risk remains unmitigated, attackers might be able to trick logged-in victim users into unwanted actions within the web application " +
			"by visiting an attacker controlled web site.",
		ASVS:         "[v4.0.3-V4.2 - Access Control Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x12-V4-Access-Control.md#v42-operation-level-access-control)",
		CheatSheet:   "[Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)",
		TestingGuide: "[v4.2-4.6.5 - Testing for Cross Site Request Forgery](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)",
		Action:       "CSRF Prevention",
		Mitigation: "Try to use anti-CSRF tokens ot the double-submit patterns (at least for logged-in requests). " +
			"When your authentication scheme depends on cookies (like session or token cookies), consider marking them with " +
			"the same-site flag. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Development,
		STRIDE:         model.Spoofing,
		DetectionLogic: "In-scope web applications accessed via typical web access protocols.",
		RiskAssessment: "The risk rating depends on the integrity rating of the data sent across the communication link.",
		FalsePositives: "Web applications passing the authentication sate via custom headers instead of cookies can " +
			"eventually be false positives. Also when the web application " +
			"is not accessed via a browser-like component (i.e not by a human user initiating the request that " +
			"gets passed through all components until it reaches the web application) this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        352,
	}
}

func (r crossSiteRequestForgeryRule) SupportedTags() []string {
	return []string{}
}

func (r crossSiteRequestForgeryRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technology.IsWebApplication() {
			continue
		}
		incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if incomingFlow.Protocol.IsPotentialWebAccessProtocol() {
				likelihood := model.VeryLikely
				if incomingFlow.Usage == model.DevOps {
					likelihood = model.Likely
				}
				risks = append(risks, createRisk(technicalAsset, incomingFlow, likelihood))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink, likelihood model.RiskExploitationLikelihood) model.Risk {
	sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>" + technicalAsset.Title + "</b> via <b>" + incomingFlow.Title + "</b> from <b>" + sourceAsset.Title + "</b>"
	impact := model.LowImpact
	if incomingFlow.HighestIntegrity() == criticality.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                        RiskRule.Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
