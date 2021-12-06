package model

import "time"

type ModelInput struct { // TODO: Eventually remove this and directly use ParsedModelRoot? But then the error messages for model errors are not quite as good anymore...
	Threagile_version                                  string
	Title                                              string
	Author                                             Author
	Date                                               string
	Business_overview                                  Overview
	Technical_overview                                 Overview
	Business_criticality                               string
	Management_summary_comment                         string
	Questions                                          map[string]string
	Abuse_cases                                        map[string]string
	Security_requirements                              map[string]string
	Tags_available                                     []string
	Data_assets                                        map[string]InputDataAsset
	Technical_assets                                   map[string]InputTechnicalAsset
	Trust_boundaries                                   map[string]InputTrustBoundary
	Shared_runtimes                                    map[string]InputSharedRuntime
	Individual_risk_categories                         map[string]InputIndividualRiskCategory
	Risk_tracking                                      map[string]InputRiskTracking
	Diagram_tweak_nodesep, Diagram_tweak_ranksep       int
	Diagram_tweak_edge_layout                          string
	Diagram_tweak_suppress_edge_labels                 bool
	Diagram_tweak_layout_left_to_right                 bool
	Diagram_tweak_invisible_connections_between_assets []string
	Diagram_tweak_same_rank_assets                     []string
}

type ParsedModel struct {
	Author                                        Author
	Title                                         string
	Date                                          time.Time
	ManagementSummaryComment                      string
	BusinessOverview                              Overview
	TechnicalOverview                             Overview
	BusinessCriticality                           Criticality
	SecurityRequirements                          map[string]string
	Questions                                     map[string]string
	AbuseCases                                    map[string]string
	TagsAvailable                                 []string
	DataAssets                                    map[string]DataAsset
	TechnicalAssets                               map[string]TechnicalAsset
	TrustBoundaries                               map[string]TrustBoundary
	SharedRuntimes                                map[string]SharedRuntime
	IndividualRiskCategories                      map[string]RiskCategory
	RiskTracking                                  map[string]RiskTracking
	DiagramTweakNodesep, DiagramTweakRanksep      int
	DiagramTweakEdgeLayout                        string
	DiagramTweakSuppressEdgeLabels                bool
	DiagramTweakLayoutLeftToRight                 bool
	DiagramTweakInvisibleConnectionsBetweenAssets []string
	DiagramTweakSameRankAssets                    []string
}

type Author struct {
	Name     string `json:"name"`
	Homepage string `json:"homepage"`
}

type Overview struct {
	Description string              `json:"description"`
	Images      []map[string]string `json:"images"` // yes, array of map here, as array keeps the order of the image keys
}
