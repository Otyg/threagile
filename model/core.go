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
	CommunicationLinks = make(map[string]CommunicationLink)
	IncomingTechnicalCommunicationLinksMappedByTargetId = make(map[string][]CommunicationLink)
	DirectContainingTrustBoundaryMappedByTechnicalAssetId = make(map[string]TrustBoundary)
	DirectContainingSharedRuntimeMappedByTechnicalAssetId = make(map[string]SharedRuntime)
	GeneratedRisksByCategory = make(map[RiskCategory][]Risk)
	GeneratedRisksBySyntheticId = make(map[string]Risk)
	AllSupportedTags = make(map[string]bool)
}

func AddToListOfSupportedTags(tags []string) {
	for _, tag := range tags {
		AllSupportedTags[tag] = true
	}
}

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

func SortedKeysOfSecurityRequirements() []string {
	keys := make([]string, 0)
	for k := range ParsedModelRoot.SecurityRequirements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SortedKeysOfAbuseCases() []string {
	keys := make([]string, 0)
	for k := range ParsedModelRoot.AbuseCases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SortedKeysOfQuestions() []string {
	keys := make([]string, 0)
	for k := range ParsedModelRoot.Questions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
