package main

import (
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
)

type unknownDataClassification string

var RiskRule unknownDataClassification

func (r unknownDataClassification) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "unknown-data-classification",
		Title:                      "Unknown Data Classification",
		Description:                "To ensure correct handling and protection all data processed by the system should be classified in regards to confidentiality, integrity and availability.",
		Impact:                     "Sensitive data might be leaked or altered by accident if not correctly classified",
		CRE:                        "[765-788: Classify sensitive data in protection levels](https://www.opencre.org/cre/765-788)",
		ASVS:                       "[v4.0.3-V1.8 - Data Protection and Privacy Architecture](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x10-V1-Architecture.md#v18-data-protection-and-privacy-architecture)",
		CheatSheet:                 "[User Privacy Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)",
		TestingGuide:               "",
		Action:                     "Data protection",
		Mitigation:                 "Ensure all data assets has a known classification",
		Check:                      "Referenced ASVS chapters and cheat sheets",
		Function:                   model.Architecture,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Data assets with any of the properties Confidentiality, Integrity, Availability set to unknown",
		RiskAssessment:             "Until the data asset has been correctly classified, it should be treated as sensitive; hence the impact is set to high.",
		FalsePositives:             "None",
		ModelFailurePossibleReason: true,
		CWE:                        668,
	}
}
func (r unknownDataClassification) SupportedTags() []string {
	return []string{}
}
func (r unknownDataClassification) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, dataAsset := range model.SortedDataAssetsByTitle() {
		if dataAsset.Availability == criticality.Unknown ||
			dataAsset.Integrity == criticality.Unknown ||
			dataAsset.Confidentiality == confidentiality.Unknown {
			risks = append(risks, createRisk(dataAsset))
		}
	}
	return risks
}
func createRisk(dataAsset model.DataAsset) model.Risk {
	title := "<b>" + RiskRule.Category().Title + "</b> risk at <b>" + dataAsset.Title + "</b>"
	risk := model.Risk{
		Category:               RiskRule.Category(),
		Severity:               model.CalculateSeverity(model.Likely, model.HighImpact),
		ExploitationLikelihood: model.Likely,
		ExploitationImpact:     model.HighImpact,
		DataBreachProbability:  model.Possible,
		Title:                  title,
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataAsset.Id
	return risk
}
