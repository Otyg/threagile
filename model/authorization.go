package model

import (
	"errors"
	"strings"
)

type Authorization int

const (
	NoneAuthorization Authorization = iota
	TechnicalUser
	EnduserIdentityPropagation
)

func AuthorizationValues() []TypeEnum {
	return []TypeEnum{
		NoneAuthorization,
		TechnicalUser,
		EnduserIdentityPropagation,
	}
}

func (what Authorization) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"none", "technical-user", "enduser-identity-propagation"}[what]
}

func ParseAuthorization(value string) (result Authorization, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range AuthorizationValues() {
		if candidate.String() == value {
			return candidate.(Authorization), err
		}
	}
	return result, errors.New("Unable to parse into type: " + value)
}
