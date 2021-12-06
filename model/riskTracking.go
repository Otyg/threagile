package model

import "time"

type RiskTracking struct {
	SyntheticRiskId, Justification, Ticket, CheckedBy string
	Status                                            RiskStatus
	Date                                              time.Time
}
