package model

import (
	"fmt"
	"sort"
)

type InputTechnicalAsset struct {
	ID                         string                            `json:"id"`
	Description                string                            `json:"description"`
	Type                       string                            `json:"type"`
	Usage                      string                            `json:"usage"`
	Used_as_client_by_human    bool                              `json:"used_as_client_by_human"`
	Out_of_scope               bool                              `json:"out_of_scope"`
	Justification_out_of_scope string                            `json:"justification_out_of_scope"`
	Size                       string                            `json:"size"`
	Technology                 string                            `json:"technology"`
	Tags                       []string                          `json:"tags"`
	Internet                   bool                              `json:"internet"`
	Machine                    string                            `json:"machine"`
	Encryption                 string                            `json:"encryption"`
	Owner                      string                            `json:"owner"`
	Confidentiality            string                            `json:"confidentiality"`
	Integrity                  string                            `json:"integrity"`
	Availability               string                            `json:"availability"`
	Justification_cia_rating   string                            `json:"justification_cia_rating"`
	Multi_tenant               bool                              `json:"multi_tenant"`
	Redundant                  bool                              `json:"redundant"`
	Custom_developed_parts     bool                              `json:"custom_developed_parts"`
	Data_assets_processed      []string                          `json:"data_assets_processed"`
	Data_assets_stored         []string                          `json:"data_assets_stored"`
	Data_formats_accepted      []string                          `json:"data_formats_accepted"`
	Diagram_tweak_order        int                               `json:"diagram_tweak_order"`
	Communication_links        map[string]InputCommunicationLink `json:"communication_links"`
}
type TechnicalAsset struct {
	Id, Title, Description                                                                  string
	Usage                                                                                   Usage
	Type                                                                                    TechnicalAssetType
	Size                                                                                    TechnicalAssetSize
	Technology                                                                              TechnicalAssetTechnology
	Machine                                                                                 TechnicalAssetMachine
	Internet, MultiTenant, Redundant, CustomDevelopedParts, OutOfScope, UsedAsClientByHuman bool
	Encryption                                                                              EncryptionStyle
	JustificationOutOfScope                                                                 string
	Owner                                                                                   string
	Confidentiality                                                                         Confidentiality
	Integrity, Availability                                                                 Criticality
	JustificationCiaRating                                                                  string
	Tags, DataAssetsProcessed, DataAssetsStored                                             []string
	DataFormatsAccepted                                                                     []DataFormat
	CommunicationLinks                                                                      []CommunicationLink
	DiagramTweakOrder                                                                       int
	// will be set by separate calculation step:
	RAA float64
}

func (what TechnicalAsset) IsTaggedWithAny(tags ...string) bool {
	return ContainsCaseInsensitiveAny(what.Tags, tags...)
}

func (what TechnicalAsset) IsTaggedWithBaseTag(basetag string) bool {
	return IsTaggedWithBaseTag(what.Tags, basetag)
}

// first use the tag(s) of the asset itself, then their trust boundaries (recursively up) and then their shared runtime
func (what TechnicalAsset) IsTaggedWithAnyTraversingUp(tags ...string) bool {
	if ContainsCaseInsensitiveAny(what.Tags, tags...) {
		return true
	}
	tbID := what.GetTrustBoundaryId()
	if len(tbID) > 0 {
		if ParsedModelRoot.TrustBoundaries[tbID].IsTaggedWithAnyTraversingUp(tags...) {
			return true
		}
	}
	for _, sr := range ParsedModelRoot.SharedRuntimes {
		if Contains(sr.TechnicalAssetsRunning, what.Id) && sr.IsTaggedWithAny(tags...) {
			return true
		}
	}
	return false
}

func (what TechnicalAsset) IsSameTrustBoundary(otherAssetId string) bool {
	trustBoundaryOfMyAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	trustBoundaryOfOtherAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}

func (what TechnicalAsset) IsSameExecutionEnvironment(otherAssetId string) bool {
	trustBoundaryOfMyAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	trustBoundaryOfOtherAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if trustBoundaryOfMyAsset.Type == ExecutionEnvironment && trustBoundaryOfOtherAsset.Type == ExecutionEnvironment {
		return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
	}
	return false
}

func (what TechnicalAsset) IsSameTrustBoundaryNetworkOnly(otherAssetId string) bool {
	trustBoundaryOfMyAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	if !trustBoundaryOfMyAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfMyAsset = ParsedModelRoot.TrustBoundaries[trustBoundaryOfMyAsset.ParentTrustBoundaryID()]
	}
	trustBoundaryOfOtherAsset := DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if !trustBoundaryOfOtherAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfOtherAsset = ParsedModelRoot.TrustBoundaries[trustBoundaryOfOtherAsset.ParentTrustBoundaryID()]
	}
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}

func (what TechnicalAsset) HighestSensitivityScore() float64 {
	return what.Confidentiality.AttackerAttractivenessForAsset() +
		what.Integrity.AttackerAttractivenessForAsset() +
		what.Availability.AttackerAttractivenessForAsset()
}

func (what TechnicalAsset) HighestConfidentiality() Confidentiality {
	highest := what.Confidentiality
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (what TechnicalAsset) DataAssetsProcessedSorted() []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsProcessed {
		result = append(result, ParsedModelRoot.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (what TechnicalAsset) DataAssetsStoredSorted() []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsStored {
		result = append(result, ParsedModelRoot.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (what TechnicalAsset) DataFormatsAcceptedSorted() []DataFormat {
	result := make([]DataFormat, 0)
	for _, format := range what.DataFormatsAccepted {
		result = append(result, format)
	}
	sort.Sort(ByDataFormatAcceptedSort(result))
	return result
}

func (what TechnicalAsset) CommunicationLinksSorted() []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, format := range what.CommunicationLinks {
		result = append(result, format)
	}
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

func (what TechnicalAsset) HighestIntegrity() Criticality {
	highest := what.Integrity
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (what TechnicalAsset) HighestAvailability() Criticality {
	highest := what.Availability
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := ParsedModelRoot.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (what TechnicalAsset) HasDirectConnection(otherAssetId string) bool {
	for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
		if dataFlow.SourceId == otherAssetId {
			return true
		}
	}
	// check both directions, hence two times, just reversed
	for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[otherAssetId] {
		if dataFlow.SourceId == what.Id {
			return true
		}
	}
	return false
}

func (what TechnicalAsset) GeneratedRisks() []Risk {
	resultingRisks := make([]Risk, 0)
	if len(SortedRiskCategories()) == 0 {
		fmt.Println("Uh, strange, no risks generated (yet?) and asking for them by tech asset...")
	}
	for _, category := range SortedRiskCategories() {
		risks := SortedRisksOfCategory(category)
		for _, risk := range risks {
			if risk.MostRelevantTechnicalAssetId == what.Id {
				resultingRisks = append(resultingRisks, risk)
			}
		}
	}
	sort.Sort(ByRiskSeveritySort(resultingRisks))
	return resultingRisks
}

/*
func (what TechnicalAsset) HighestRiskSeverity() RiskSeverity {
	highest := Low
	for _, risk := range what.GeneratedRisks() {
		if risk.Severity > highest {
			highest = risk.Severity
		}
	}
	return highest
}
*/

type TechnicalAssetSize int

const (
	System TechnicalAssetSize = iota
	Service
	Application
	Component
)

func TechnicalAssetSizeValues() []TypeEnum {
	return []TypeEnum{
		System,
		Service,
		Application,
		Component,
	}
}

func (what TechnicalAssetSize) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"system", "service", "application", "component"}[what]
}

type TechnicalAssetTechnology int

const (
	UnknownTechnology TechnicalAssetTechnology = iota
	ClientSystem
	Browser
	Desktop
	MobileApp
	DevOpsClient
	WebServer
	WebApplication
	ApplicationServer
	Database
	FileServer
	LocalFileSystem
	ERP
	CMS
	WebServiceREST
	WebServiceSOAP
	EJB
	SearchIndex
	SearchEngine
	ServiceRegistry
	ReverseProxy
	LoadBalancer
	BuildPipeline
	SourcecodeRepository
	ArtifactRegistry
	CodeInspectionPlatform
	Monitoring
	LDAPServer
	ContainerPlatform
	BatchProcessing
	EventListener
	IdentityProvider
	IdentityStoreLDAP
	IdentityStoreDatabase
	Tool
	CLI
	Task
	Function
	Gateway // TODO rename to API-Gateway to be more clear?
	IoTDevice
	MessageQueue
	StreamProcessing
	ServiceMesh
	DataLake
	BigDataPlatform
	ReportEngine
	AI
	MailServer
	Vault
	HSM
	WAF
	IDS
	IPS
	Scheduler
	Mainframe
	BlockStorage
	Library
)

func TechnicalAssetTechnologyValues() []TypeEnum {
	return []TypeEnum{
		UnknownTechnology,
		ClientSystem,
		Browser,
		Desktop,
		MobileApp,
		DevOpsClient,
		WebServer,
		WebApplication,
		ApplicationServer,
		Database,
		FileServer,
		LocalFileSystem,
		ERP,
		CMS,
		WebServiceREST,
		WebServiceSOAP,
		EJB,
		SearchIndex,
		SearchEngine,
		ServiceRegistry,
		ReverseProxy,
		LoadBalancer,
		BuildPipeline,
		SourcecodeRepository,
		ArtifactRegistry,
		CodeInspectionPlatform,
		Monitoring,
		LDAPServer,
		ContainerPlatform,
		BatchProcessing,
		EventListener,
		IdentityProvider,
		IdentityStoreLDAP,
		IdentityStoreDatabase,
		Tool,
		CLI,
		Task,
		Function,
		Gateway,
		IoTDevice,
		MessageQueue,
		StreamProcessing,
		ServiceMesh,
		DataLake,
		BigDataPlatform,
		ReportEngine,
		AI,
		MailServer,
		Vault,
		HSM,
		WAF,
		IDS,
		IPS,
		Scheduler,
		Mainframe,
		BlockStorage,
		Library,
	}
}

func (what TechnicalAssetTechnology) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unknown-technology", "client-system", "browser", "desktop", "mobile-app", "devops-client",
		"web-server", "web-application", "application-server", "database", "file-server", "local-file-system", "erp", "cms",
		"web-service-rest", "web-service-soap", "ejb", "search-index", "search-engine", "service-registry", "reverse-proxy",
		"load-balancer", "build-pipeline", "sourcecode-repository", "artifact-registry", "code-inspection-platform", "monitoring", "ldap-server",
		"container-platform", "batch-processing", "event-listener", "identity-provider", "identity-store-ldap",
		"identity-store-database", "tool", "cli", "task", "function", "gateway", "iot-device", "message-queue", "stream-processing",
		"service-mesh", "data-lake", "big-data-platform", "report-engine", "ai", "mail-server", "vault", "hsm", "waf", "ids", "ips",
		"scheduler", "mainframe", "block-storage", "library"}[what]
}

func (what TechnicalAssetTechnology) IsWebApplication() bool {
	return what == WebServer || what == WebApplication || what == ApplicationServer || what == ERP || what == CMS || what == IdentityProvider || what == ReportEngine
}

func (what TechnicalAssetTechnology) IsWebService() bool {
	return what == WebServiceREST || what == WebServiceSOAP
}

func (what TechnicalAssetTechnology) IsIdentityRelated() bool {
	return what == IdentityProvider || what == IdentityStoreLDAP || what == IdentityStoreDatabase
}

func (what TechnicalAssetTechnology) IsSecurityControlRelated() bool {
	return what == Vault || what == HSM || what == WAF || what == IDS || what == IPS
}

func (what TechnicalAssetTechnology) IsUnprotectedCommsTolerated() bool {
	return what == Monitoring || what == IDS || what == IPS
}

func (what TechnicalAssetTechnology) IsUnnecessaryDataTolerated() bool {
	return what == Monitoring || what == IDS || what == IPS
}

func (what TechnicalAssetTechnology) IsCloseToHighValueTargetsTolerated() bool {
	return what == Monitoring || what == IDS || what == IPS || what == LoadBalancer || what == ReverseProxy
}

func (what TechnicalAssetTechnology) IsClient() bool {
	return what == ClientSystem || what == Browser || what == Desktop || what == MobileApp || what == DevOpsClient || what == IoTDevice
}

func (what TechnicalAssetTechnology) IsUsuallyAbleToPropagateIdentityToOutgoingTargets() bool {
	return what == ClientSystem || what == Browser || what == Desktop || what == MobileApp ||
		what == DevOpsClient || what == WebServer || what == WebApplication || what == ApplicationServer || what == ERP ||
		what == CMS || what == WebServiceREST || what == WebServiceSOAP || what == EJB ||
		what == SearchEngine || what == ReverseProxy || what == LoadBalancer || what == IdentityProvider ||
		what == Tool || what == CLI || what == Task || what == Function || what == Gateway ||
		what == IoTDevice || what == MessageQueue || what == ServiceMesh || what == ReportEngine || what == WAF || what == Library

}

func (what TechnicalAssetTechnology) IsLessProtectedType() bool {
	return what == ClientSystem || what == Browser || what == Desktop || what == MobileApp || what == DevOpsClient || what == WebServer || what == WebApplication || what == ApplicationServer || what == CMS ||
		what == WebServiceREST || what == WebServiceSOAP || what == EJB || what == BuildPipeline || what == SourcecodeRepository ||
		what == ArtifactRegistry || what == CodeInspectionPlatform || what == Monitoring || what == IoTDevice || what == AI || what == MailServer || what == Scheduler ||
		what == Mainframe
}

func (what TechnicalAssetTechnology) IsUsuallyProcessingEnduserRequests() bool {
	return what == WebServer || what == WebApplication || what == ApplicationServer || what == ERP || what == WebServiceREST || what == WebServiceSOAP || what == EJB || what == ReportEngine
}

func (what TechnicalAssetTechnology) IsUsuallyStoringEnduserData() bool {
	return what == Database || what == ERP || what == FileServer || what == LocalFileSystem || what == BlockStorage || what == MailServer || what == StreamProcessing || what == MessageQueue
}

func (what TechnicalAssetTechnology) IsExclusivelyFrontendRelated() bool {
	return what == ClientSystem || what == Browser || what == Desktop || what == MobileApp || what == DevOpsClient || what == CMS || what == ReverseProxy || what == WAF || what == LoadBalancer || what == Gateway || what == IoTDevice
}

func (what TechnicalAssetTechnology) IsExclusivelyBackendRelated() bool {
	return what == Database || what == IdentityProvider || what == IdentityStoreLDAP || what == IdentityStoreDatabase || what == ERP || what == WebServiceREST || what == WebServiceSOAP || what == EJB || what == SearchIndex ||
		what == SearchEngine || what == ContainerPlatform || what == BatchProcessing || what == EventListener || what == DataLake || what == BigDataPlatform || what == MessageQueue ||
		what == StreamProcessing || what == ServiceMesh || what == Vault || what == HSM || what == Scheduler || what == Mainframe || what == FileServer || what == BlockStorage
}

func (what TechnicalAssetTechnology) IsDevelopmentRelevant() bool {
	return what == BuildPipeline || what == SourcecodeRepository || what == ArtifactRegistry || what == CodeInspectionPlatform || what == DevOpsClient
}

func (what TechnicalAssetTechnology) IsTrafficForwarding() bool {
	return what == LoadBalancer || what == ReverseProxy || what == WAF
}

func (what TechnicalAssetTechnology) IsEmbeddedComponent() bool {
	return what == Library
}

type TechnicalAssetMachine int

const (
	Physical TechnicalAssetMachine = iota
	Virtual
	Container
	Serverless
)

func TechnicalAssetMachineValues() []TypeEnum {
	return []TypeEnum{
		Physical,
		Virtual,
		Container,
		Serverless,
	}
}

func (what TechnicalAssetMachine) String() string {
	return [...]string{"physical", "virtual", "container", "serverless"}[what]
}
