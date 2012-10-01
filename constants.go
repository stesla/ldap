package ldap

const ldapVersion = 3

const (
	ldapBindRequest = 0
	ldapBindResponse = 1
)

const ( // LDAP Response Codes
	ldapSuccess = 0
)

const ( // ASN.1 class codes
	classUniversal = 0
	classApplication = 1
	classContext = 2
	classPrivate = 3
)
