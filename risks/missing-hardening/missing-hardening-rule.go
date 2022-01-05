package main

import (
	"strconv"

	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type missingHardening string

var RiskRule missingHardening

const raaLimit = 55
const raaLimitReduced = 40

func (r missingHardening) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-hardening",
		Title: "Missing Hardening",
		Description: "Technical assets with a Relative Attacker Attractiveness (RAA) value of " + strconv.Itoa(raaLimit) + " % or higher should be " +
			"explicitly hardened taking best practices and vendor hardening guides into account.",
		Impact:       "If this risk remains unmitigated, attackers might be able to easier attack high-value targets.",
		ASVS:         "[v.4.0.3-V14 - Configuration Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x22-V14-Config.md)",
		CheatSheet:   "[Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)",
		TestingGuide: "[v4.2-4.2 - Configuration and Deployment Management Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing)",
		Action:       "System Hardening",
		Mitigation: "Try to apply all hardening best practices (like CIS benchmarks, OWASP recommendations, vendor " +
			"recommendations, DevSec Hardening Framework, DBSAT for Oracle databases, and others).",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: model.Operations,
		STRIDE:   model.Tampering,
		DetectionLogic: "In-scope technical assets with RAA values of " + strconv.Itoa(raaLimit) + " % or higher. " +
			"Generally for high-value targets like datastores, application servers, identity providers and ERP systems this limit is reduced to " + strconv.Itoa(raaLimitReduced) + " %",
		RiskAssessment:             "The risk rating depends on the sensitivity of the data processed or stored in the technical asset.",
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        16,
	}
}

func (r missingHardening) SupportedTags() []string {
	return []string{"tomcat"}
}

func (r missingHardening) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			if technicalAsset.RAA >= raaLimit || (technicalAsset.RAA >= raaLimitReduced &&
				(technicalAsset.Type == model.Datastore || technicalAsset.Technology == model.ApplicationServer || technicalAsset.Technology == model.IdentityProvider || technicalAsset.Technology == model.ERP)) {
				risks = append(risks, createRisk(technicalAsset))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Missing Hardening</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() == confidentiality.StrictlyConfidential || technicalAsset.HighestIntegrity() == criticality.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood:       model.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
