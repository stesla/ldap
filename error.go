package ldap

type LDAPError struct {
	Msg string
}

func (e LDAPError) Error() string { return "LDAP error: " + e.Msg }

var notimpl = LDAPError{"Not Implemented"}
