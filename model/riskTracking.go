package model

import "time"

type RiskTracking struct {
	SyntheticRiskId, Justification, Ticket, CheckedBy string
	Status                                            RiskStatus
	Date                                              time.Time
}
type InputRiskTracking struct {
	Status        string `json:"status"`
	Justification string `json:"justification"`
	Ticket        string `json:"ticket"`
	Date          string `json:"date"`
	Checked_by    string `json:"checked_by"`
}
