package ldap

import (
	"github.com/stesla/ldap/asn1"
)

type Filter interface{}

func And(filters ...Filter) Filter {
	return asn1.OptionValue{"tag:0,set", filters}
}

func Or(filters ...Filter) Filter {
	return asn1.OptionValue{"tag:1,set", filters}
}

func Not(filter Filter) Filter {
	return asn1.OptionValue{"tag:2", filter}
}

type attributeValueAssertion struct {
	Attribute, Value []byte
}

func Equals(attribute, value string) Filter {
	val := attributeValueAssertion{[]byte(attribute), []byte(value)}
	return asn1.OptionValue{"tag:3", val}
}

func Present(attribute string) Filter {
	return asn1.OptionValue{"tag:7", []byte(attribute)}
}

type matchingRuleAssertion struct {
	MatchingRule []byte `asn1:"tag:1,optional"`
	Type         []byte `asn1:"tag:2,optional"`
	MatchValue   []byte `asn1:"tag:3"`
	DnAttributes bool   `asn1:"tag:4"`
}

func Matches(rule, attribute, value string) Filter {
	val := matchingRuleAssertion{
		[]byte(rule), []byte(attribute), []byte(value), false}
	return asn1.OptionValue{"tag:9", val}
}
