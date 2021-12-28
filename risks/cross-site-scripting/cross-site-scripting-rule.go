package main

import (
	"github.com/otyg/threagile/model"
)

type crossSiteScriptingRule string

var RiskRule crossSiteScriptingRule

func (r crossSiteScriptingRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "cross-site-scripting",
		Title: "Cross-Site Scripting (XSS)",
		Description: "For each web application Cross-Site Scripting (XSS) risks might arise. In terms " +
			"of the overall risk level take other applications running on the same domain into account as well.",
		Impact:       "If this risk remains unmitigated, attackers might be able to access individual victim sessions and steal or modify user data.",
		ASVS:         "[v4.0.3-V5 - Validation, Sanitization and Encoding Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md)",
		CheatSheet:   "[Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
		TestingGuide: "[v4.2-4.7 - Input Validation Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing)",
		Action:       "XSS Prevention",
		Mitigation: "Try to encode all values sent back to the browser and also handle DOM-manipulations in a safe way " +
			"to avoid DOM-based XSS. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Development,
		STRIDE:         model.Tampering,
		DetectionLogic: "In-scope web applications.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored in the web application.",
		FalsePositives: "When the technical asset " +
			"is not accessed via a browser-like component (i.e not by a human user initiating the request that " +
			"gets passed through all components until it reaches the web application) this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        79,
	}
}

func (r crossSiteScriptingRule) SupportedTags() []string {
	return []string{}
}

func (r crossSiteScriptingRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technology.IsWebApplication() { // TODO: also mobile clients or rich-clients as long as they use web-view...
			continue
		}
		risks = append(risks, createRisk(technicalAsset))
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Cross-Site Scripting (XSS)</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
	}
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood:       model.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
