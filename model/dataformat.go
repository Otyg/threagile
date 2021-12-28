package model

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type DataFormat int

const (
	JSON DataFormat = iota
	XML
	Serialization
	File
	CSV
)

func DataFormatValues() []core.TypeEnum {
	return []core.TypeEnum{
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

func ParseDataFormatName(value string) (dataFormat DataFormat, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range DataFormatValues() {
		if candidate.String() == value {
			return candidate.(DataFormat), err
		}
	}
	return dataFormat, errors.New("Unable to parse into type: " + value)
}

type ByDataFormatAcceptedSort []DataFormat

func (what ByDataFormatAcceptedSort) Len() int      { return len(what) }
func (what ByDataFormatAcceptedSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataFormatAcceptedSort) Less(i, j int) bool {
	return what[i].String() < what[j].String()
}
