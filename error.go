package ldap

import (
	"errors"
)

var notimpl = errors.New("Not Implemented")

type LDAPError struct {
	Msg string
}

func (e LDAPError) Error() string { return "LDAP error: " + e.Msg }
