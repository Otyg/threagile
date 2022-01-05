package model

import (
	"errors"
	"strings"

	"github.com/otyg/threagile/model/core"
)

type Authentication int

const (
	NoneAuthentication Authentication = iota
	Credentials
	SessionId
	Token
	ClientCertificate
	TwoFactor
	Externalized
)

func AuthenticationValues() []core.TypeEnum {
	return []core.TypeEnum{
		NoneAuthentication,
		Credentials,
		SessionId,
		Token,
		ClientCertificate,
		TwoFactor,
		Externalized,
	}
}

func (what Authentication) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"none", "credentials", "session-id", "token", "client-certificate", "two-factor", "externalized"}[what]
}

func ParseAuthentication(value string) (authentication Authentication, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range AuthenticationValues() {
		if candidate.String() == value {
			return candidate.(Authentication), err
		}
	}
	return authentication, errors.New("Unable to parse into type: " + value)
}
