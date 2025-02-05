package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
)

type useOfWeakCrypto string

var RiskRule useOfWeakCrypto

func (r useOfWeakCrypto) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "use-of-weak-cryptograhpy-at-rest",
		Title:                      "Use Of Weak Cryptography At Rest",
		Description:                "To avoid weak cryptography ensure to use algoritms, modes and libraries that has been vetted and proven by industry and/or governments.",
		Impact:                     "Weak cryptography can result in information disclosure and a false sense of security.",
		ASVS:                       "[v4.0.3-V6.2 - Stored cryptography: Algorithms](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x14-V6-Cryptography.md#v62-algorithms)",
		CheatSheet:                 "[Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)",
		TestingGuide:               "[v4.2-4.9.4: Testing for Weak Encryption](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption)",
		Action:                     "Cryptography",
		Mitigation:                 "Ensure to use algoritms, modes and libraries that has been vetted and proven by industry and/or governments.",
		Check:                      "Referenced ASVS chapters and cheat sheets",
		Function:                   model.Development,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Encrypted technical assets that stores data",
		RiskAssessment:             "Risk is based on the confidentiality score of stored data.",
		FalsePositives:             "None",
		ModelFailurePossibleReason: false,
		CWE:                        327,
	}
}
func (r useOfWeakCrypto) SupportedTags() []string {
	return []string{}
}
func (r useOfWeakCrypto) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if techAsset.OutOfScope || techAsset.Technology.IsClient() {
			continue
		}
		if techAsset.Encryption != model.NoneEncryption {
			var mostRelevantDataAssetId string
			var highestConfidentiality confidentiality.Confidentiality = confidentiality.Public
			var impact model.RiskExploitationImpact
			for _, data := range techAsset.DataAssetsStoredSorted() {
				if data.Confidentiality >= highestConfidentiality {
					mostRelevantDataAssetId = data.Id
					highestConfidentiality = data.Confidentiality
					switch data.Confidentiality {
					case confidentiality.Restricted:
						impact = model.MediumImpact
					case confidentiality.Confidential:
						impact = model.HighImpact
					case confidentiality.StrictlyConfidential:
						impact = model.VeryHighImpact
					default:
						impact = model.LowImpact
					}
				}
			}
			risks = append(risks, createRisk(techAsset, impact, mostRelevantDataAssetId))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, mostRelevantDataAssetId string) model.Risk {
	title := "<b>Use of weak cryptography at rest</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
		MostRelevantDataAssetId:      mostRelevantDataAssetId,
		DataBreachProbability:        model.Possible,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
