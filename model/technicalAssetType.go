package model

type TechnicalAssetType int

const (
	ExternalEntity TechnicalAssetType = iota
	Process
	Datastore
)

func TechnicalAssetTypeValues() []TypeEnum {
	return []TypeEnum{
		ExternalEntity,
		Process,
		Datastore,
	}
}

func (what TechnicalAssetType) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"external-entity", "process", "datastore"}[what]
}
