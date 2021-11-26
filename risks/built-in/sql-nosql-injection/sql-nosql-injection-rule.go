package sql_nosql_injection

import (
	"github.com/otyg/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "sql-nosql-injection",
		Title: "SQL/NoSQL-Injection",
		Description: "When a database is accessed via database access protocols SQL/NoSQL-Injection risks might arise. " +
			"The risk rating depends on the sensitivity technical asset itself and of the data assets processed or stored.",
		Impact:       "If this risk is unmitigated, attackers might be able to modify SQL/NoSQL queries to steal and modify data and eventually further escalate towards a deeper system penetration via code executions.",
		ASVS:         "[v4.0.3-V5 - Validation, Sanitization and Encoding Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md)",
		CheatSheet:   "[SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
		TestingGuide: "[v4.2-4.7.5 Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)",
		Action:       "SQL/NoSQL-Injection Prevention",
		Mitigation: "Try to use parameter binding to be safe from injection vulnerabilities. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Development,
		STRIDE:         model.Tampering,
		DetectionLogic: "Database accessed via typical database access protocols by in-scope clients.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data stored inside the database.",
		FalsePositives: "Database accesses by queries not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        89,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			if incomingFlow.Protocol.IsPotentialDatabaseAccessProtocol(true) && (technicalAsset.Technology == model.Database || technicalAsset.Technology == model.IdentityStoreDatabase) ||
				(incomingFlow.Protocol.IsPotentialDatabaseAccessProtocol(false)) {
				risks = append(risks, createRisk(technicalAsset, incomingFlow))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink) model.Risk {
	caller := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>SQL/NoSQL-Injection</b> risk at <b>" + caller.Title + "</b> against database <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
	}
	likelihood := model.VeryLikely
	if incomingFlow.Usage == model.DevOps {
		likelihood = model.Likely
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           model.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
