package ldap

import (
	"github.com/stesla/ldap/asn1"
)

type Filter interface {}

func And(filters ...Filter) Filter {
	return asn1.OptionValue{"tag:0", filters}
}

func Or(filters ...Filter) Filter {
	return nil
}

func Not(filter Filter) Filter {
	return nil
}

type attributeValueAssertion struct {
	description, value []byte
}

func Equals(description, value string) Filter {
	val := attributeValueAssertion{[]byte(description),	[]byte(value)}
	return asn1.OptionValue{"tag:3", val}
}
