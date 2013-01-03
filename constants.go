package ldap

const ldapVersion = 3

const (
	ldapBindRequest   = 0
	ldapBindResponse  = 1
	ldapUnbindRequest = 2
)

const ( // LDAP Response Codes
	ldapSuccess = 0
)

const ( // ASN.1 class codes
	classUniversal   = 0
	classApplication = 1
	classContext     = 2
	classPrivate     = 3
)

const ( // ASN.1 tags
	tagOctetString = 4
	tagNull        = 5
)
