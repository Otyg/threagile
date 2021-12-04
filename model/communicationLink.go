package model

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
