package model

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
