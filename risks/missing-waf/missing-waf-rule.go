package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type missingWaf string

var RiskRule missingWaf

func (r missingWaf) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-waf",
		Title: "Missing Web Application Firewall (WAF)",
		Description: "To have a first line of filtering defense, security architectures with web-services or web-applications should include a WAF in front of them. " +
			"Even though a WAF is not a replacement for security (all components must be secure even without a WAF) it adds another layer of defense to the overall " +
			"system by delaying some attacks and having easier attack alerting through it.",
		Impact:     "If this risk is unmitigated, attackers might be able to apply standard attack pattern tests at great speed without any filtering.",
		ASVS:       "[v4.0.3-V1 - Architecture, Design and Threat Modeling Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x10-V1-Architecture.md)",
		CheatSheet: "[Virtual Patching Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html)",
		Action:     "Web Application Firewall (WAF)",
		Mitigation: "Consider placing a Web Application Firewall (WAF) in front of the web-services and/or web-applications. For cloud environments many cloud providers offer " +
			"pre-configured WAFs. Even reverse proxies can be enhances by a WAF component via ModSecurity plugins.",
		Check:          "Is a Web Application Firewall (WAF) in place?",
		Function:       model.Operations,
		STRIDE:         model.Tampering,
		DetectionLogic: "In-scope web-services and/or web-applications accessed across a network trust boundary not having a Web Application Firewall (WAF) in front of them.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed and stored.",
		FalsePositives: "Targets only accessible via WAFs or reverse proxies containing a WAF component (like ModSecurity) can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func (r missingWaf) SupportedTags() []string {
	return []string{}
}

func (r missingWaf) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope &&
			(technicalAsset.Technology.IsWebApplication() || technicalAsset.Technology.IsWebService()) {
			for _, incomingAccess := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				if incomingAccess.IsAcrossTrustBoundaryNetworkOnly() &&
					incomingAccess.Protocol.IsPotentialWebAccessProtocol() &&
					model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Technology != model.WAF {
					risks = append(risks, createRisk(technicalAsset))
					break
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Missing Web Application Firewall (WAF)</b> risk at <b>" + technicalAsset.Title + "</b>"
	likelihood := model.Unlikely
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() == confidentiality.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == criticality.MissionCritical ||
		technicalAsset.HighestAvailability() == criticality.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
