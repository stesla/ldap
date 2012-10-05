package asn1

import (
	"reflect"
	"testing"
)

type parseIdentTest struct {
	in []byte
	ok bool
	out tlvType
}

var parseIdentTests = []parseIdentTest {
	{[]byte{}, false, tlvType{}},
	{[]byte{0x1f, 0x85}, false, tlvType{}},
	{[]byte{0x00}, true, tlvType{0, 0, false}},
	{[]byte{0x80}, true, tlvType{2, 0, false}},
	{[]byte{0xa0}, true, tlvType{2, 0, true}},
	{[]byte{0x41}, true, tlvType{1, 1, false}},
	{[]byte{0xfe}, true, tlvType{3, 30, true}},
	{[]byte{0x1f, 0x01}, true, tlvType{0, 1, false}},
	{[]byte{0x1f, 0x81, 0x00}, true, tlvType{0, 128, false}},
	{[]byte{0x1f, 0x81, 0x80, 0x01}, true, tlvType{0, 0x4001, false}},
}

func TestParseType(t *testing.T) {
	for i, test := range parseIdentTests {
		ident, rem, err := parseType(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (passed? %v, expected %v)",
				i, err == nil, test.ok)
		}
		if err == nil && !reflect.DeepEqual(test.out, ident) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ident, test.out)
		}
		if len(rem) != 0 {
			t.Errorf("#%d: Did not consume all bytes, %d remaining", i, len(rem))
		}
	}
}

type parseLengthTest struct {
	in []byte
	ok bool
	out tlvLength
}

var parseLengthTests = []parseLengthTest {
	// Good Input
	{[]byte{0x81, 0x01}, true, tlvLength{1, false}},
	{[]byte{0x82, 0x01, 0x00}, true, tlvLength{256, false}},
	{[]byte{0x80}, true, tlvLength{0, true}},
	// Errors
	{[]byte{}, false, tlvLength{}},
	{[]byte{0x83, 0x01, 0x00}, false, tlvLength{}},
	{[]byte{0xff}, false, tlvLength{}},
}

func TestParseLength(t *testing.T) {
	for i, test := range parseLengthTests {
		l, rem, err := parseLength(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (actual = %v, expected = %v)",
				i, err == nil, test.ok)
		}
		if err == nil && !reflect.DeepEqual(test.out, l) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, l, test.out)
		}
		if err == nil && len(rem) != 0 {
			t.Errorf("#%d: Did not consume all bytes, %d remaining", i, len(rem))
		}
	}
}

