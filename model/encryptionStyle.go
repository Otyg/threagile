package model

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type EncryptionStyle int

const (
	Unknown EncryptionStyle = iota
	NoneEncryption
	Transparent
	DataWithSymmetricSharedKey
	DataWithAsymmetricSharedKey
	DataWithEnduserIndividualKey
)

func EncryptionStyleValues() []core.TypeEnum {
	return []core.TypeEnum{
		Unknown,
		NoneEncryption,
		Transparent,
		DataWithSymmetricSharedKey,
		DataWithAsymmetricSharedKey,
		DataWithEnduserIndividualKey,
	}
}

func ParseEncryptionStyle(value string) (encryptionStyle EncryptionStyle, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range EncryptionStyleValues() {
		if candidate.String() == value {
			return candidate.(EncryptionStyle), err
		}
	}
	return encryptionStyle, errors.New("Unable to parse into type: " + value)
}

func (what EncryptionStyle) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unknown", "none", "transparent", "data-with-symmetric-shared-key", "data-with-asymmetric-shared-key", "data-with-enduser-individual-key"}[what]
}

func (what EncryptionStyle) Title() string {
	return [...]string{"Unknown", "None", "Transparent", "Data with Symmetric Shared Key", "Data with Asymmetric Shared Key", "Data with Enduser Individual Key"}[what]
}
