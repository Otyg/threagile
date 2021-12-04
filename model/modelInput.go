package model

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

type InputDataAsset struct {
	ID                       string   `json:"id"`
	Description              string   `json:"description"`
	Usage                    string   `json:"usage"`
	Tags                     []string `json:"tags"`
	Origin                   string   `json:"origin"`
	Owner                    string   `json:"owner"`
	Quantity                 string   `json:"quantity"`
	Confidentiality          string   `json:"confidentiality"`
	Integrity                string   `json:"integrity"`
	Availability             string   `json:"availability"`
	Justification_cia_rating string   `json:"justification_cia_rating"`
}

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

type InputSharedRuntime struct {
	ID                       string   `json:"id"`
	Description              string   `json:"description"`
	Tags                     []string `json:"tags"`
	Technical_assets_running []string `json:"technical_assets_running"`
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

type InputRiskIdentified struct {
	Severity                         string   `json:"severity"`
	Exploitation_likelihood          string   `json:"exploitation_likelihood"`
	Exploitation_impact              string   `json:"exploitation_impact"`
	Data_breach_probability          string   `json:"data_breach_probability"`
	Data_breach_technical_assets     []string `json:"data_breach_technical_assets"`
	Most_relevant_data_asset         string   `json:"most_relevant_data_asset"`
	Most_relevant_technical_asset    string   `json:"most_relevant_technical_asset"`
	Most_relevant_communication_link string   `json:"most_relevant_communication_link"`
	Most_relevant_trust_boundary     string   `json:"most_relevant_trust_boundary"`
	Most_relevant_shared_runtime     string   `json:"most_relevant_shared_runtime"`
}

type InputRiskTracking struct {
	Status        string `json:"status"`
	Justification string `json:"justification"`
	Ticket        string `json:"ticket"`
	Date          string `json:"date"`
	Checked_by    string `json:"checked_by"`
}
