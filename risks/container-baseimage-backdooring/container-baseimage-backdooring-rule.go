package main

import (
	"github.com/otyg/threagile/model"
)

type containerBackdooringRule string

var RiskRule containerBackdooringRule

func (r containerBackdooringRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "container-baseimage-backdooring",
		Title: "Container Base Image Backdooring",
		Description: "When a technical asset is built using container technologies, Base Image Backdooring risks might arise where " +
			"base images and other layers used contain vulnerable components or backdoors." +
			"<br><br>See for example: <a href=\"https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/\">https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/</a>",
		Impact:     "If this risk is unmitigated, attackers might be able to deeply persist in the target system by executing code in deployed containers.",
		ASVS:       "[v4.0.3-V10 - Malicious Code Verification Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x18-V10-Malicious.md)",
		CheatSheet: "[Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)",
		Action:     "Container Infrastructure Hardening",
		Mitigation: "Apply hardening of all container infrastructures (see for example the <i>CIS-Benchmarks for Docker and Kubernetes</i> and the <i>Docker Bench for Security</i>). " +
			"Use only trusted base images of the original vendors, verify digital signatures and apply image creation best practices. " +
			"Also consider using Google's <i>Distroless</i> base images or otherwise very small base images. " +
			"Regularly execute container image scans with tools checking the layers for vulnerable components.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS/CSVS applied?",
		Function:       model.Operations,
		STRIDE:         model.Tampering,
		DetectionLogic: "In-scope technical assets running as containers.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets.",
		FalsePositives: "Fully trusted (i.e. reviewed and cryptographically signed or similar) base images of containers can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        912,
	}
}

func (r containerBackdooringRule) SupportedTags() []string {
	return []string{}
}

func (r containerBackdooringRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Machine == model.Container {
			risks = append(risks, createRisk(technicalAsset))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Container Base Image Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.HighImpact
	}
	risk := model.Risk{
		Category:                     RiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
