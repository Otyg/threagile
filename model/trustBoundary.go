package model

import (
	"errors"
	"sort"
	"strings"

	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/core"
	"github.com/otyg/threagile/model/criticality"
)

type InputTrustBoundary struct {
	ID                      string   `json:"id"`
	Description             string   `json:"description"`
	Type                    string   `json:"type"`
	Tags                    []string `json:"tags"`
	Technical_assets_inside []string `json:"technical_assets_inside"`
	Trust_boundaries_nested []string `json:"trust_boundaries_nested"`
}

type TrustBoundary struct {
	Id, Title, Description string
	Type                   TrustBoundaryType
	Tags                   []string
	TechnicalAssetsInside  []string
	TrustBoundariesNested  []string
}

func (what TrustBoundary) IsTaggedWithAny(tags ...string) bool {
	return ContainsCaseInsensitiveAny(what.Tags, tags...)
}

func (what TrustBoundary) IsTaggedWithBaseTag(basetag string) bool {
	return IsTaggedWithBaseTag(what.Tags, basetag)
}

func (what TrustBoundary) IsTaggedWithAnyTraversingUp(tags ...string) bool {
	if what.IsTaggedWithAny(tags...) {
		return true
	}
	parentID := what.ParentTrustBoundaryID()
	if len(parentID) > 0 && ParsedModelRoot.TrustBoundaries[parentID].IsTaggedWithAnyTraversingUp(tags...) {
		return true
	}
	return false
}

func (what TrustBoundary) ParentTrustBoundaryID() string {
	var result string
	for _, candidate := range ParsedModelRoot.TrustBoundaries {
		if Contains(candidate.TrustBoundariesNested, what.Id) {
			result = candidate.Id
			return result
		}
	}
	return result
}

func (what TrustBoundary) HighestConfidentiality() confidentiality.Confidentiality {
	highest := confidentiality.Public
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside() {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestConfidentiality() > highest {
			highest = techAsset.HighestConfidentiality()
		}
	}
	return highest
}

func (what TrustBoundary) HighestIntegrity() criticality.Criticality {
	highest := criticality.Archive
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside() {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestIntegrity() > highest {
			highest = techAsset.HighestIntegrity()
		}
	}
	return highest
}

func (what TrustBoundary) HighestAvailability() criticality.Criticality {
	highest := criticality.Archive
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside() {
		techAsset := ParsedModelRoot.TechnicalAssets[id]
		if techAsset.HighestAvailability() > highest {
			highest = techAsset.HighestAvailability()
		}
	}
	return highest
}

type TrustBoundaryType int

const (
	NetworkOnPrem TrustBoundaryType = iota
	NetworkDedicatedHoster
	NetworkVirtualLAN
	NetworkCloudProvider
	NetworkCloudSecurityGroup
	NetworkPolicyNamespaceIsolation
	ExecutionEnvironment
)

func TrustBoundaryTypeValues() []core.TypeEnum {
	return []core.TypeEnum{
		NetworkOnPrem,
		NetworkDedicatedHoster,
		NetworkVirtualLAN,
		NetworkCloudProvider,
		NetworkCloudSecurityGroup,
		NetworkPolicyNamespaceIsolation,
		ExecutionEnvironment,
	}
}

func (what TrustBoundaryType) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"network-on-prem", "network-dedicated-hoster", "network-virtual-lan",
		"network-cloud-provider", "network-cloud-security-group", "network-policy-namespace-isolation",
		"execution-environment"}[what]
}

func ParseTrustBoundaryType(value string) (result TrustBoundaryType, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range TrustBoundaryTypeValues() {
		if candidate.String() == value {
			return candidate.(TrustBoundaryType), err
		}
	}
	return result, errors.New("Unable to parse into type: " + value)
}
func (what TrustBoundaryType) IsNetworkBoundary() bool {
	return what == NetworkOnPrem || what == NetworkDedicatedHoster || what == NetworkVirtualLAN ||
		what == NetworkCloudProvider || what == NetworkCloudSecurityGroup || what == NetworkPolicyNamespaceIsolation
}

func (what TrustBoundaryType) IsWithinCloud() bool {
	return what == NetworkCloudProvider || what == NetworkCloudSecurityGroup
}

func (what TrustBoundary) RecursivelyAllTechnicalAssetIDsInside() []string {
	result := make([]string, 0)
	what.addAssetIDsRecursively(&result)
	return result
}

func (what TrustBoundary) addAssetIDsRecursively(result *[]string) {
	*result = append(*result, what.TechnicalAssetsInside...)
	for _, nestedBoundaryID := range what.TrustBoundariesNested {
		ParsedModelRoot.TrustBoundaries[nestedBoundaryID].addAssetIDsRecursively(result)
	}
}

func (what TrustBoundary) AllParentTrustBoundaryIDs() []string {
	result := make([]string, 0)
	what.addTrustBoundaryIDsRecursively(&result)
	return result
}

func (what TrustBoundary) addTrustBoundaryIDsRecursively(result *[]string) {
	*result = append(*result, what.Id)
	parentID := what.ParentTrustBoundaryID()
	if len(parentID) > 0 {
		ParsedModelRoot.TrustBoundaries[parentID].addTrustBoundaryIDsRecursively(result)
	}
}

func IsSharingSameParentTrustBoundary(left, right TechnicalAsset) bool {
	tbIDLeft, tbIDRight := left.GetTrustBoundaryId(), right.GetTrustBoundaryId()
	if len(tbIDLeft) == 0 && len(tbIDRight) > 0 {
		return false
	}
	if len(tbIDLeft) > 0 && len(tbIDRight) == 0 {
		return false
	}
	if len(tbIDLeft) == 0 && len(tbIDRight) == 0 {
		return true
	}
	if tbIDLeft == tbIDRight {
		return true
	}
	tbLeft, tbRight := ParsedModelRoot.TrustBoundaries[tbIDLeft], ParsedModelRoot.TrustBoundaries[tbIDRight]
	tbParentsLeft, tbParentsRight := tbLeft.AllParentTrustBoundaryIDs(), tbRight.AllParentTrustBoundaryIDs()
	for _, parentLeft := range tbParentsLeft {
		for _, parentRight := range tbParentsRight {
			if parentLeft == parentRight {
				return true
			}
		}
	}
	return false
}

func TrustBoundariesTaggedWithAny(tags ...string) []TrustBoundary {
	result := make([]TrustBoundary, 0)
	for _, candidate := range ParsedModelRoot.TrustBoundaries {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func SortedKeysOfTrustBoundaries() []string {
	keys := make([]string, 0)
	for k := range ParsedModelRoot.TrustBoundaries {
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

type ByTrustBoundaryTitleSort []TrustBoundary

func (what ByTrustBoundaryTitleSort) Len() int      { return len(what) }
func (what ByTrustBoundaryTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTrustBoundaryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
