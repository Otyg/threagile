package support

import (
	"errors"
	"regexp"
)

var validIdSyntax = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)

func CheckIdSyntax(id string) {
	if !validIdSyntax.MatchString(id) {
		panic(errors.New("invalid id syntax used (only letters, numbers, and hyphen allowed): " + id))
	}
}
