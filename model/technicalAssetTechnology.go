package model

import (
	"errors"
	"strings"
)

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

func ParseTechnicalAssetTechnology(value string) (technicalAssetTechnology TechnicalAssetTechnology, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range TechnicalAssetTechnologyValues() {
		if candidate.String() == value {
			return candidate.(TechnicalAssetTechnology), err
		}
	}
	return technicalAssetTechnology, errors.New("Unable to parse into technology: " + value)
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
