package ldap

import (
	"github.com/stesla/ldap/asn1"
)

type Filter interface{}

func And(filters ...Filter) Filter {
	return asn1.OptionValue{Opts: "tag:0,set", Value: filters}
}

func Or(filters ...Filter) Filter {
	return asn1.OptionValue{Opts: "tag:1,set", Value: filters}
}

func Not(filter Filter) Filter {
	return asn1.OptionValue{Opts: "tag:2", Value: filter}
}

type attributeValueAssertion struct {
	Attribute, Value []byte
}

func Equals(attribute, value string) Filter {
	val := attributeValueAssertion{[]byte(attribute), []byte(value)}
	return asn1.OptionValue{Opts: "tag:3", Value: val}
}

func Present(attribute string) Filter {
	return asn1.OptionValue{Opts: "tag:7", Value: []byte(attribute)}
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
	return asn1.OptionValue{Opts: "tag:9", Value: val}
}
