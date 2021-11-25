package credential_stored_outside_of_vault

import (
	"github.com/otyg/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "credential-stored-outside-of-vault",
		Title:                      "Credential Stored Outside Of Vault",
		Description:                "Secret data, such as credentials and encryption keys, must be protected and managed in a secure way to minimize the risk of exposure. The recommended solution is to keep secret data in a dedicated system (vault) and only store access credentials to this system on other technical assets.",
		Impact:                     "If a hardcoded secret is exposed considerable work must be done to rotate it",
		ASVS:                       "[v4.0.2-V6.4 - Secret Management](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x14-V6-Cryptography.md#v64-secret-management)",
		CheatSheet:                 "[Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)",
		TestingGuide:               "[v4.2-4.9: Testing for Weak Cryptography](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography)",
		Action:                     "Secret management",
		Mitigation:                 "Manage secrets and credentials according to ASVS and the cheat sheets referenced",
		Check:                      "Is secret data (i.e. credentials) protected well enough? Has relevant parts of referenced ASVS and cheat sheets been applied?",
		Function:                   model.Operations,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Data assets tagged with any of the supported tags is stored on a technical asset that is not a vault",
		RiskAssessment:             "Impact and severity is calculated based on the tags available on the data asset and the confidentiality class of the technical asset storing the credential.",
		FalsePositives:             "Stored autorotated credentials with short lifetime can be considered a false positive after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        522,
	}
}

func SupportedTags() []string {
	return []string{"credential", "credential-lifetime:unknown/hardcoded", "credential-lifetime:unlimited", "credential-lifetime:long", "credential-lifetime:short", "credential-lifetime:auto-rotation", "credential-lifetime:manual-rotation"}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, data := range model.DataAssetsTaggedWithAny(SupportedTags()...) {
		// credential-lifetime:unlimited set as default
		exploitationImpact := model.MediumImpact
		exploitationProbability := model.Frequent
		dataBreachProbability := model.Probable
		if data.IsTaggedWithAny("credential-lifetime:unknown/hardcoded") || !data.IsTaggedWithAny("credential-lifetime:unlimited", "credential-lifetime:long", "credential-lifetime:short") {
			// If only credential-tag is present, assume unknown
			exploitationImpact = model.HighImpact
		} else if data.IsTaggedWithAny("credential-lifetime:long") {
			exploitationProbability = model.VeryLikely
		} else if data.IsTaggedWithAny("credential-lifetime:short") {
			exploitationProbability = model.Likely
		}
		if data.IsTaggedWithAny("credential-lifetime:manual-rotation", "credential-lifetime:auto-rotation") && !data.IsTaggedWithAny("credential-lifetime:unknown/hardcoded") {
			exploitationImpact = exploitationImpact - 1
			exploitationProbability = exploitationProbability - 1
			dataBreachProbability = model.Possible
		}
		for _, technicalAsset := range data.StoredByTechnicalAssetsSorted() {
			if technicalAsset.OutOfScope || technicalAsset.Technology == model.Vault {
				continue
			}
			if technicalAsset.Confidentiality == model.StrictlyConfidential && technicalAsset.Encryption != model.NoneEncryption {
				// Assume that a technical asset classed for Strictly Confidential is well protected
				if exploitationProbability > model.Unlikely {
					exploitationProbability = exploitationProbability - 1
				}
				dataBreachProbability = model.Improbable
			}
			risks = append(risks, createRisk(technicalAsset, exploitationImpact, exploitationProbability, data.Id, dataBreachProbability))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, probability model.RiskExploitationLikelihood, mostCriticalDataId string, dataProbability model.DataBreachProbability) model.Risk {
	title := "<b>Credential stored outside of vault</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(probability, impact),
		ExploitationLikelihood:       probability,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		MostRelevantDataAssetId:      mostCriticalDataId,
		DataBreachProbability:        dataProbability,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
