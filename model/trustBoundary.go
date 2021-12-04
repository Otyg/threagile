package model

type InputTrustBoundary struct {
	ID                      string   `json:"id"`
	Description             string   `json:"description"`
	Type                    string   `json:"type"`
	Tags                    []string `json:"tags"`
	Technical_assets_inside []string `json:"technical_assets_inside"`
	Trust_boundaries_nested []string `json:"trust_boundaries_nested"`
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

func TrustBoundaryTypeValues() []TypeEnum {
	return []TypeEnum{
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
