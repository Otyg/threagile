package model

import "sort"

type InputCommunicationLink struct {
	Target                   string   `json:"target"`
	Description              string   `json:"description"`
	Protocol                 string   `json:"protocol"`
	Authentication           string   `json:"authentication"`
	Authorization            string   `json:"authorization"`
	Tags                     []string `json:"tags"`
	VPN                      bool     `json:"vpn"`
	IP_filtered              bool     `json:"ip_filtered"`
	Readonly                 bool     `json:"readonly"`
	Usage                    string   `json:"usage"`
	Data_assets_sent         []string `json:"data_assets_sent"`
	Data_assets_received     []string `json:"data_assets_received"`
	Diagram_tweak_weight     int      `json:"diagram_tweak_weight"`
	Diagram_tweak_constraint bool     `json:"diagram_tweak_constraint"`
}
type CommunicationLink struct {
	Id, SourceId, TargetId, Title, Description string
	Protocol                                   Protocol
	Tags                                       []string
	VPN, IpFiltered, Readonly                  bool
	Authentication                             Authentication
	Authorization                              Authorization
	Usage                                      Usage
	DataAssetsSent, DataAssetsReceived         []string
	DiagramTweakWeight                         int
	DiagramTweakConstraint                     bool
}

func (what CommunicationLink) IsTaggedWithAny(tags ...string) bool {
	return ContainsCaseInsensitiveAny(what.Tags, tags...)
}

func (what CommunicationLink) IsTaggedWithBaseTag(basetag string) bool {
	return IsTaggedWithBaseTag(what.Tags, basetag)
}

func (what CommunicationLink) IsAcrossTrustBoundary() bool {
	trustBoundaryOfSourceAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.SourceId]
	trustBoundaryOfTargetAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.TargetId]
	return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id
}

func (what CommunicationLink) IsAcrossTrustBoundaryNetworkOnly() bool {
	trustBoundaryOfSourceAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.SourceId]
	if !trustBoundaryOfSourceAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfSourceAsset = ParsedModelRoot.TrustBoundaries[trustBoundaryOfSourceAsset.ParentTrustBoundaryID()]
	}
	trustBoundaryOfTargetAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.TargetId]
	if !trustBoundaryOfTargetAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfTargetAsset = ParsedModelRoot.TrustBoundaries[trustBoundaryOfTargetAsset.ParentTrustBoundaryID()]
	}
	return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id && trustBoundaryOfTargetAsset.Type.IsNetworkBoundary()
}

func (what CommunicationLink) HighestConfidentiality() Confidentiality {
	highest := Public
	for _, dataId := range what.DataAssetsSent {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (what CommunicationLink) HighestIntegrity() Criticality {
	highest := Archive
	for _, dataId := range what.DataAssetsSent {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (what CommunicationLink) HighestAvailability() Criticality {
	highest := Archive
	for _, dataId := range what.DataAssetsSent {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (what CommunicationLink) DataAssetsSentSorted() []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsSent {
		result = append(result, ParsedModelRoot.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (what CommunicationLink) DataAssetsReceivedSorted() []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsReceived {
		result = append(result, ParsedModelRoot.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}
