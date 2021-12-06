package model

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
