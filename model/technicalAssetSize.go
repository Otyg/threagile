package model

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
