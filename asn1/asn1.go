package asn1

import (
	"reflect"
	"strconv"
	"strings"
)

const ( // ASN.1 Classes
	ClassUniversal       = 0 // 0b00
	ClassApplication     = 1 // 0b01
	ClassContextSpecific = 2 // 0b10
	ClassPrivate         = 3 // 0b11
)

const ( // ASN.1 Universal Tags
	// TagEndOfContent     = 0x00
	TagBoolean = 0x01
	TagInteger = 0x02
	// TagBitString        = 0x03
	TagOctetString = 0x04
	TagNull        = 0x05
	// TagObjectIdentifier = 0x06
	// TagObjectDescriptor = 0x07
	// TagExternal         = 0x08
	// TagReal             = 0x09
	TagEnumerated = 0x0a
	// TagEmbeddedPDV      = 0x0b
	// TagUTF8String       = 0x0c
	// TagRelativeOID      = 0x0d
	TagSequence = 0x10
	TagSet      = 0x11
	// TagNumericString    = 0x12
	// TagPrintableString  = 0x13
	// TagT61String        = 0x14
	// TagVideotexString   = 0x15
	// TagIA5String        = 0x16
	// TagUTCTime          = 0x17
	// TagGeneralizedTime  = 0x18
	// TagGraphicString    = 0x19
	// TagVisibleString    = 0x1a
	// TagGeneralString    = 0x1b
	// TagUniversalString  = 0x1c
	// TagCharacterString  = 0x1d
	// TagBMPString        = 0x1e
)

type StructuralError string

func (e StructuralError) Error() string { return "ASN.1 Structural Error: " + string(e) }

type SyntaxError string

func (e SyntaxError) Error() string { return "ASN.1 Syntax Error: " + string(e) }

type RawValue struct {
	Class, Tag  int
	Constructed bool
	Bytes       []byte
	RawBytes    []byte
}

type OptionValue struct {
	Opts  string
	Value interface{}
}

type fieldOptions struct {
	tag         *int
	implicit    *bool
	application bool
	optional    bool
	enum        bool
	set         bool
	components  bool
}

var (
	optionValueType = reflect.TypeOf(OptionValue{})
	rawValueType    = reflect.TypeOf(RawValue{})
)

func parseFieldOptions(s string) (ret fieldOptions) {
	for _, part := range strings.Split(s, ",") {
		switch {
		case part == "application":
			ret.application = true
			if ret.tag == nil {
				ret.tag = new(int)
			}
		case part == "implicit":
			ret.implicit = new(bool)
			*ret.implicit = true
			if ret.tag == nil {
				ret.tag = new(int)
			}
		case part == "explicit":
			ret.implicit = new(bool)
			if ret.tag == nil {
				ret.tag = new(int)
			}
		case strings.HasPrefix(part, "tag:"):
			i, err := strconv.Atoi(part[4:])
			if err == nil {
				ret.tag = new(int)
				*ret.tag = i
			}
		case part == "optional":
			ret.optional = true
		case part == "enum":
			ret.enum = true
		case part == "set":
			ret.set = true
		case part == "components":
			ret.components = true
		}
	}
	return
}

func dereference(v reflect.Value, opts fieldOptions) (reflect.Value, fieldOptions) {
	for {
		if v.Type() == optionValueType {
			vv := v.Interface().(OptionValue)
			opts = parseFieldOptions(vv.Opts)
			v = reflect.ValueOf(vv.Value)
		} else if k := v.Kind(); k == reflect.Ptr || k == reflect.Interface {
			v = v.Elem()
		} else {
			break
		}
	}
	return v, opts
}
