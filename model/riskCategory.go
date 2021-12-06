package model

import "sort"

type RiskCategory struct {
	// TODO: refactor all "Id" here and elsewhere to "ID"
	Id                         string
	Title                      string
	Description                string
	Impact                     string
	ASVS                       string
	CheatSheet                 string
	TestingGuide               string
	Action                     string
	Mitigation                 string
	Check                      string
	DetectionLogic             string
	RiskAssessment             string
	FalsePositives             string
	Function                   RiskFunction
	STRIDE                     STRIDE
	ModelFailurePossibleReason bool
	CWE                        int
}

type InputIndividualRiskCategory struct {
	ID                            string                         `json:"id"`
	Description                   string                         `json:"description"`
	Impact                        string                         `json:"impact"`
	ASVS                          string                         `json:"asvs"`
	Cheat_sheet                   string                         `json:"cheat_sheet"`
	Testing_guide                 string                         `json:"testing_guide"`
	Action                        string                         `json:"action"`
	Mitigation                    string                         `json:"mitigation"`
	Check                         string                         `json:"check"`
	Function                      string                         `json:"function"`
	STRIDE                        string                         `json:"stride"`
	Detection_logic               string                         `json:"detection_logic"`
	Risk_assessment               string                         `json:"risk_assessment"`
	False_positives               string                         `json:"false_positives"`
	Model_failure_possible_reason bool                           `json:"model_failure_possible_reason"`
	CWE                           int                            `json:"cwe"`
	Risks_identified              map[string]InputRiskIdentified `json:"risks_identified"`
}

func SortedKeysOfIndividualRiskCategories() []string {
	keys := make([]string, 0)
	for k := range ParsedModelRoot.IndividualRiskCategories {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type ByRiskCategoryTitleSort []RiskCategory

func (what ByRiskCategoryTitleSort) Len() int { return len(what) }
func (what ByRiskCategoryTitleSort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskCategoryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk []RiskCategory

func (what ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk) Len() int { return len(what) }
func (what ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk) Less(i, j int) bool {
	risksLeft := ReduceToOnlyStillAtRisk(GeneratedRisksByCategory[what[i]])
	risksRight := ReduceToOnlyStillAtRisk(GeneratedRisksByCategory[what[j]])
	highestLeft := HighestSeverityStillAtRisk(risksLeft)
	highestRight := HighestSeverityStillAtRisk(risksRight)
	if highestLeft == highestRight {
		if len(risksLeft) == 0 && len(risksRight) > 0 {
			return false
		}
		if len(risksLeft) > 0 && len(risksRight) == 0 {
			return true
		}
		return what[i].Title < what[j].Title
	}
	return highestLeft > highestRight
}
func SortedRiskCategories() []RiskCategory {
	categories := make([]RiskCategory, 0)
	for k := range GeneratedRisksByCategory {
		categories = append(categories, k)
	}
	sort.Sort(ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(categories))
	return categories
}

func CategoriesOfOnlyRisksStillAtRisk(risksByCategory map[RiskCategory][]Risk) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			categories[risk.Category] = struct{}{}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyCriticalRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			if risk.Severity == CriticalSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyHighRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(GeneratedRisksByCategory[risk.Category])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(GeneratedRisksByCategory[risk.Category])
			}
			if risk.Severity == HighSeverity && highest < CriticalSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyElevatedRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(GeneratedRisksByCategory[risk.Category])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(GeneratedRisksByCategory[risk.Category])
			}
			if risk.Severity == ElevatedSeverity && highest < HighSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyMediumRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(GeneratedRisksByCategory[risk.Category])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(GeneratedRisksByCategory[risk.Category])
			}
			if risk.Severity == MediumSeverity && highest < ElevatedSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyLowRisks(risksByCategory map[RiskCategory][]Risk, initialRisks bool) []RiskCategory {
	categories := make(map[RiskCategory]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(GeneratedRisksByCategory[risk.Category])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(GeneratedRisksByCategory[risk.Category])
			}
			if risk.Severity == LowSeverity && highest < MediumSeverity {
				categories[risk.Category] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func keysAsSlice(categories map[RiskCategory]struct{}) []RiskCategory {
	result := make([]RiskCategory, 0, len(categories))
	for k := range categories {
		result = append(result, k)
	}
	return result
}
