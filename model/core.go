package model

import (
	"regexp"
	"sort"
	"strings"
)

var ThreagileVersion = ""     // Also update into example and stub model files and openapi.yaml
const TempFolder = "/dev/shm" // TODO: make configurable via cmdline arg?

var ParsedModelRoot ParsedModel

var CommunicationLinks map[string]CommunicationLink // TODO as part of "ParsedModelRoot"?
var IncomingTechnicalCommunicationLinksMappedByTargetId map[string][]CommunicationLink
var DirectContainingTrustBoundaryMappedByTechnicalAssetId map[string]TrustBoundary
var DirectContainingSharedRuntimeMappedByTechnicalAssetId map[string]SharedRuntime

var GeneratedRisksByCategory map[RiskCategory][]Risk
var GeneratedRisksBySyntheticId map[string]Risk

var AllSupportedTags map[string]bool

func Init() {
	CommunicationLinks = make(map[string]CommunicationLink, 0)
	IncomingTechnicalCommunicationLinksMappedByTargetId = make(map[string][]CommunicationLink, 0)
	DirectContainingTrustBoundaryMappedByTechnicalAssetId = make(map[string]TrustBoundary, 0)
	DirectContainingSharedRuntimeMappedByTechnicalAssetId = make(map[string]SharedRuntime, 0)
	GeneratedRisksByCategory = make(map[RiskCategory][]Risk, 0)
	GeneratedRisksBySyntheticId = make(map[string]Risk, 0)
	AllSupportedTags = make(map[string]bool, 0)
}

func AddToListOfSupportedTags(tags []string) {
	for _, tag := range tags {
		AllSupportedTags[tag] = true
	}
}

// === To be used by model macros etc. =======================

func AddTagToModelInput(modelInput *ModelInput, tag string, dryRun bool, changes *[]string) {
	tag = NormalizeTag(tag)
	if !Contains(modelInput.Tags_available, tag) {
		*changes = append(*changes, "adding tag: "+tag)
		if !dryRun {
			modelInput.Tags_available = append(modelInput.Tags_available, tag)
		}
	}
}

func NormalizeTag(tag string) string {
	return strings.TrimSpace(strings.ToLower(tag))
}

func MakeID(val string) string {
	reg, _ := regexp.Compile("[^A-Za-z0-9]+")
	return strings.Trim(reg.ReplaceAllString(strings.ToLower(val), "-"), "- ")
}

type TypeEnum interface {
	String() string
}

func IsTaggedWithBaseTag(tags []string, basetag string) bool { // basetags are before the colon ":" like in "aws:ec2" it's "aws". The subtag is after the colon. Also a pure "aws" tag matches the basetag "aws"
	basetag = strings.ToLower(strings.TrimSpace(basetag))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == basetag || strings.HasPrefix(tag, basetag+":") {
			return true
		}
	}
	return false
}

type ByTrustBoundaryTitleSort []TrustBoundary

func (what ByTrustBoundaryTitleSort) Len() int      { return len(what) }
func (what ByTrustBoundaryTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTrustBoundaryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type BySharedRuntimeTitleSort []SharedRuntime

func (what BySharedRuntimeTitleSort) Len() int      { return len(what) }
func (what BySharedRuntimeTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what BySharedRuntimeTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByDataFormatAcceptedSort []DataFormat

func (what ByDataFormatAcceptedSort) Len() int      { return len(what) }
func (what ByDataFormatAcceptedSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataFormatAcceptedSort) Less(i, j int) bool {
	return what[i].String() < what[j].String()
}

func TagsActuallyUsed() []string {
	result := make([]string, 0)
	for _, tag := range ParsedModelRoot.TagsAvailable {
		if len(TechnicalAssetsTaggedWithAny(tag)) > 0 ||
			len(CommunicationLinksTaggedWithAny(tag)) > 0 ||
			len(DataAssetsTaggedWithAny(tag)) > 0 ||
			len(TrustBoundariesTaggedWithAny(tag)) > 0 ||
			len(SharedRuntimesTaggedWithAny(tag)) > 0 {
			result = append(result, tag)
		}
	}
	return result
}

// === Sorting stuff =====================================

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfIndividualRiskCategories() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.IndividualRiskCategories {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfSecurityRequirements() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.SecurityRequirements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfAbuseCases() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.AbuseCases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfQuestions() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.Questions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func TrustBoundariesTaggedWithAny(tags ...string) []TrustBoundary {
	result := make([]TrustBoundary, 0)
	for _, candidate := range ParsedModelRoot.TrustBoundaries {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func SharedRuntimesTaggedWithAny(tags ...string) []SharedRuntime {
	result := make([]SharedRuntime, 0)
	for _, candidate := range ParsedModelRoot.SharedRuntimes {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfTrustBoundaries() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SortedTrustBoundariesByTitle() []TrustBoundary {
	boundaries := make([]TrustBoundary, 0)
	for _, boundary := range ParsedModelRoot.TrustBoundaries {
		boundaries = append(boundaries, boundary)
	}
	sort.Sort(ByTrustBoundaryTitleSort(boundaries))
	return boundaries
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedKeysOfSharedRuntime() []string {
	keys := make([]string, 0)
	for k, _ := range ParsedModelRoot.SharedRuntimes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SortedSharedRuntimesByTitle() []SharedRuntime {
	result := make([]SharedRuntime, 0)
	for _, runtime := range ParsedModelRoot.SharedRuntimes {
		result = append(result, runtime)
	}
	sort.Sort(BySharedRuntimeTitleSort(result))
	return result
}

func QuestionsUnanswered() int {
	result := 0
	for _, answer := range ParsedModelRoot.Questions {
		if len(strings.TrimSpace(answer)) == 0 {
			result++
		}
	}
	return result
}

// === Style stuff =======================================

// Line Styles:

// Contains tells whether a contains x (in an unsorted slice)
func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func ContainsCaseInsensitiveAny(a []string, x ...string) bool {
	for _, n := range a {
		for _, c := range x {
			if strings.TrimSpace(strings.ToLower(c)) == strings.TrimSpace(strings.ToLower(n)) {
				return true
			}
		}
	}
	return false
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

type RiskStatistics struct {
	// TODO add also some more like before / after (i.e. with mitigation applied)
	Risks map[string]map[string]int `json:"risks"`
}

type ByRiskSeveritySort []Risk

func (what ByRiskSeveritySort) Len() int { return len(what) }
func (what ByRiskSeveritySort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskSeveritySort) Less(i, j int) bool {
	if what[i].Severity == what[j].Severity {
		trackingStatusLeft := what[i].GetRiskTrackingStatusDefaultingUnchecked()
		trackingStatusRight := what[j].GetRiskTrackingStatusDefaultingUnchecked()
		if trackingStatusLeft == trackingStatusRight {
			impactLeft := what[i].ExploitationImpact
			impactRight := what[j].ExploitationImpact
			if impactLeft == impactRight {
				likelihoodLeft := what[i].ExploitationLikelihood
				likelihoodRight := what[j].ExploitationLikelihood
				if likelihoodLeft == likelihoodRight {
					return what[i].Title < what[j].Title
				} else {
					return likelihoodLeft > likelihoodRight
				}
			} else {
				return impactLeft > impactRight
			}
		} else {
			return trackingStatusLeft < trackingStatusRight
		}
	}
	return what[i].Severity > what[j].Severity
}

type ByDataBreachProbabilitySort []Risk

func (what ByDataBreachProbabilitySort) Len() int { return len(what) }
func (what ByDataBreachProbabilitySort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByDataBreachProbabilitySort) Less(i, j int) bool {
	if what[i].DataBreachProbability == what[j].DataBreachProbability {
		trackingStatusLeft := what[i].GetRiskTrackingStatusDefaultingUnchecked()
		trackingStatusRight := what[j].GetRiskTrackingStatusDefaultingUnchecked()
		if trackingStatusLeft == trackingStatusRight {
			return what[i].Title < what[j].Title
		} else {
			return trackingStatusLeft < trackingStatusRight
		}
	}
	return what[i].DataBreachProbability > what[j].DataBreachProbability
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func SortedRiskCategories() []RiskCategory {
	categories := make([]RiskCategory, 0)
	for k, _ := range GeneratedRisksByCategory {
		categories = append(categories, k)
	}
	sort.Sort(ByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(categories))
	return categories
}
func SortedRisksOfCategory(category RiskCategory) []Risk {
	risks := GeneratedRisksByCategory[category]
	sort.Sort(ByRiskSeveritySort(risks))
	return risks
}

func CountRisks(risksByCategory map[RiskCategory][]Risk) int {
	result := 0
	for _, risks := range risksByCategory {
		result += len(risks)
	}
	return result
}

func RisksOfOnlySTRIDESpoofing(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == Spoofing {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDETampering(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == Tampering {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDERepudiation(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == Repudiation {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEInformationDisclosure(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == InformationDisclosure {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEDenialOfService(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == DenialOfService {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEElevationOfPrivilege(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == ElevationOfPrivilege {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyBusinessSide(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == BusinessSide {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyArchitecture(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Architecture {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyDevelopment(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Development {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyOperation(risksByCategory map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Operations {
				result[risk.Category] = append(result[risk.Category], risk)
			}
		}
	}
	return result
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

func HighestSeverity(risks []Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result {
			result = risk.Severity
		}
	}
	return result
}

func HighestSeverityStillAtRisk(risks []Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result && risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
			result = risk.Severity
		}
	}
	return result
}

func keysAsSlice(categories map[RiskCategory]struct{}) []RiskCategory {
	result := make([]RiskCategory, 0, len(categories))
	for k := range categories {
		result = append(result, k)
	}
	return result
}

func FilteredByOnlyBusinessSide() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == BusinessSide {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyArchitecture() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Architecture {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyDevelopment() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Development {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyOperation() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == Operations {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyCriticalRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == CriticalSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyHighRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == HighSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyElevatedRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == ElevatedSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyMediumRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == MediumSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyLowRisks() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == LowSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilterByModelFailures(risksByCat map[RiskCategory][]Risk) map[RiskCategory][]Risk {
	result := make(map[RiskCategory][]Risk, 0)
	for riskCat, risks := range risksByCat {
		if riskCat.ModelFailurePossibleReason {
			result[riskCat] = risks
		}
	}
	return result
}

func FlattenRiskSlice(risksByCat map[RiskCategory][]Risk) []Risk {
	result := make([]Risk, 0)
	for _, risks := range risksByCat {
		result = append(result, risks...)
	}
	return result
}

func TotalRiskCount() int {
	count := 0
	for _, risks := range GeneratedRisksByCategory {
		count += len(risks)
	}
	return count
}

func FilteredByRiskTrackingUnchecked() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == Unchecked {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingInDiscussion() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == InDiscussion {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingAccepted() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == Accepted {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingInProgress() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == InProgress {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingMitigated() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == Mitigated {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingFalsePositive() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked() == FalsePositive {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func ReduceToOnlyHighRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == HighSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyMediumRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == MediumSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyLowRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == LowSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingUnchecked(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == Unchecked {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingInDiscussion(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == InDiscussion {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingAccepted(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == Accepted {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingInProgress(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == InProgress {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingMitigated(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == Mitigated {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingFalsePositive(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked() == FalsePositive {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func FilteredByStillAtRisk() []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func OverallRiskStatistics() RiskStatistics {
	result := RiskStatistics{}
	result.Risks = make(map[string]map[string]int)
	result.Risks[CriticalSeverity.String()] = make(map[string]int)
	result.Risks[CriticalSeverity.String()][Unchecked.String()] = 0
	result.Risks[CriticalSeverity.String()][InDiscussion.String()] = 0
	result.Risks[CriticalSeverity.String()][Accepted.String()] = 0
	result.Risks[CriticalSeverity.String()][InProgress.String()] = 0
	result.Risks[CriticalSeverity.String()][Mitigated.String()] = 0
	result.Risks[CriticalSeverity.String()][FalsePositive.String()] = 0
	result.Risks[HighSeverity.String()] = make(map[string]int)
	result.Risks[HighSeverity.String()][Unchecked.String()] = 0
	result.Risks[HighSeverity.String()][InDiscussion.String()] = 0
	result.Risks[HighSeverity.String()][Accepted.String()] = 0
	result.Risks[HighSeverity.String()][InProgress.String()] = 0
	result.Risks[HighSeverity.String()][Mitigated.String()] = 0
	result.Risks[HighSeverity.String()][FalsePositive.String()] = 0
	result.Risks[ElevatedSeverity.String()] = make(map[string]int)
	result.Risks[ElevatedSeverity.String()][Unchecked.String()] = 0
	result.Risks[ElevatedSeverity.String()][InDiscussion.String()] = 0
	result.Risks[ElevatedSeverity.String()][Accepted.String()] = 0
	result.Risks[ElevatedSeverity.String()][InProgress.String()] = 0
	result.Risks[ElevatedSeverity.String()][Mitigated.String()] = 0
	result.Risks[ElevatedSeverity.String()][FalsePositive.String()] = 0
	result.Risks[MediumSeverity.String()] = make(map[string]int)
	result.Risks[MediumSeverity.String()][Unchecked.String()] = 0
	result.Risks[MediumSeverity.String()][InDiscussion.String()] = 0
	result.Risks[MediumSeverity.String()][Accepted.String()] = 0
	result.Risks[MediumSeverity.String()][InProgress.String()] = 0
	result.Risks[MediumSeverity.String()][Mitigated.String()] = 0
	result.Risks[MediumSeverity.String()][FalsePositive.String()] = 0
	result.Risks[LowSeverity.String()] = make(map[string]int)
	result.Risks[LowSeverity.String()][Unchecked.String()] = 0
	result.Risks[LowSeverity.String()][InDiscussion.String()] = 0
	result.Risks[LowSeverity.String()][Accepted.String()] = 0
	result.Risks[LowSeverity.String()][InProgress.String()] = 0
	result.Risks[LowSeverity.String()][Mitigated.String()] = 0
	result.Risks[LowSeverity.String()][FalsePositive.String()] = 0
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			result.Risks[risk.Severity.String()][risk.GetRiskTrackingStatusDefaultingUnchecked().String()]++
		}
	}
	return result
}

func AllRisks() []Risk {
	result := make([]Risk, 0)
	for _, risks := range GeneratedRisksByCategory {
		for _, risk := range risks {
			result = append(result, risk)
		}
	}
	return result
}

func ReduceToOnlyStillAtRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked().IsStillAtRisk() {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func HighestExploitationLikelihood(risks []Risk) RiskExploitationLikelihood {
	result := Unlikely
	for _, risk := range risks {
		if risk.ExploitationLikelihood > result {
			result = risk.ExploitationLikelihood
		}
	}
	return result
}

func HighestExploitationImpact(risks []Risk) RiskExploitationImpact {
	result := LowImpact
	for _, risk := range risks {
		if risk.ExploitationImpact > result {
			result = risk.ExploitationImpact
		}
	}
	return result
}
