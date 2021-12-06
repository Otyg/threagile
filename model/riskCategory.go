package model

type RiskCategory struct {
	// TODO: refactor all "Id" here and elsewhere to "ID"
	Id                         string
	Title                      string
	Description                string
	Impact                     string
	ASVS                       string
	CheatSheet                 string
	TestingGuide               string
	Action                     string
	Mitigation                 string
	Check                      string
	DetectionLogic             string
	RiskAssessment             string
	FalsePositives             string
	Function                   RiskFunction
	STRIDE                     STRIDE
	ModelFailurePossibleReason bool
	CWE                        int
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
