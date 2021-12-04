package model

type DataFormat int

const (
	JSON DataFormat = iota
	XML
	Serialization
	File
	CSV
)

func DataFormatValues() []TypeEnum {
	return []TypeEnum{
		JSON,
		XML,
		Serialization,
		File,
		CSV,
	}
}

func (what DataFormat) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"json", "xml", "serialization", "file", "csv"}[what]
}

func (what DataFormat) Title() string {
	return [...]string{"JSON", "XML", "Serialization", "File", "CSV"}[what]
}

func (what DataFormat) Description() string {
	return [...]string{"JSON marshalled object data", "XML structured data", "Serialization-based object graphs",
		"File input/uploads", "CSV tabular data"}[what]
}
