package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
)

type useOfWeakCryptoInTransit string

var RiskRule useOfWeakCryptoInTransit

func (r useOfWeakCryptoInTransit) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "use-of-weak-cryptography-in-transit",
		Title:                      "Use Of Weak Cryptography in transit",
		Description:                "To ensure confidentiality during transit strong encryption must be used; weak, broken or soon to be deprecated algorithms must be avoided and recommended key lengths must be applied.",
		Impact:                     "Weak cryptography can result in information disclosure and a false sense of security.",
		ASVS:                       "[v4.0.3-V9 - Communications](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x17-V9-Communications.md)",
		CheatSheet:                 "[Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)",
		TestingGuide:               "[v4.2-4.9.1: Testing for Weak Transport Layer Security](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)",
		Action:                     "Cryptography",
		Mitigation:                 "Ensure to use algoritms, modes and libraries that has been vetted and proven by industry and/or governments and follow recommendations and guidelines.",
		Check:                      "Referenced ASVS chapters and cheat sheets",
		Function:                   model.Operations,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Encrypted communication links",
		RiskAssessment:             "Risk is based on the confidentiality score of data sent or recieved.",
		FalsePositives:             "None",
		ModelFailurePossibleReason: false,
		CWE:                        327,
	}
}
func (r useOfWeakCryptoInTransit) SupportedTags() []string {
	return []string{}
}
func (r useOfWeakCryptoInTransit) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		var mostCriticalCommlink model.CommunicationLink
		var hasEncryptedComLinks = false
		for _, comm := range technicalAsset.CommunicationLinksSorted() {
			if comm.Protocol.IsEncrypted() {
				hasEncryptedComLinks = true
				if comm.HighestConfidentiality() > mostCriticalCommlink.HighestConfidentiality() {
					mostCriticalCommlink = comm
				}
			}
		}
		if hasEncryptedComLinks {
			var mostCriticalDataAsset model.DataAsset
			for _, data := range append(mostCriticalCommlink.DataAssetsSentSorted(), mostCriticalCommlink.DataAssetsReceivedSorted()...) {
				if data.Confidentiality > mostCriticalDataAsset.Confidentiality {
					mostCriticalDataAsset = data
				}
			}
			var exploitationImpact model.RiskExploitationImpact
			switch mostCriticalDataAsset.Confidentiality {
			case confidentiality.Public:
				exploitationImpact = model.LowImpact
			case confidentiality.Internal:
				exploitationImpact = model.LowImpact
			case confidentiality.Restricted:
				exploitationImpact = model.MediumImpact
			case confidentiality.Confidential:
				exploitationImpact = model.HighImpact
			case confidentiality.StrictlyConfidential:
				exploitationImpact = model.VeryHighImpact
			}
			risks = append(risks, createRisk(technicalAsset, mostCriticalCommlink, mostCriticalDataAsset, exploitationImpact))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, commLink model.CommunicationLink, dataAsset model.DataAsset, exploitationImpact model.RiskExploitationImpact) model.Risk {
	title := "<b>Use of weak cryptography in transit</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                        RiskRule.Category(),
		Severity:                        model.CalculateSeverity(model.Unlikely, exploitationImpact),
		ExploitationLikelihood:          model.Unlikely,
		ExploitationImpact:              exploitationImpact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: commLink.Id,
		MostRelevantDataAssetId:         dataAsset.Id,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
		DataBreachProbability:           model.Possible,
	}
	risk.SyntheticId = risk.Category.Id + "@" + commLink.Id
	return risk
}
