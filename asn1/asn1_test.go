package asn1

import (
	"reflect"
	"testing"
)

type parseTest struct {
	in []byte
	ok bool
	out interface{}
}

type parseFn func([]byte)(interface{},[]byte,error)

func runParseTests(t *testing.T, tests []parseTest, parse parseFn) {
	for i, test := range tests {
		out, rem, err := parse(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (passed? %v, expected %v)",
				i, err == nil, test.ok)
		}
		if err == nil && !reflect.DeepEqual(test.out, out) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, out, test.out)
		}
		if err == nil && len(rem) != 0 {
			t.Errorf("#%d: Did not consume all bytes, %d remaining", i, len(rem))
		}
	}
}

func TestParseType(t *testing.T) {
	fn := func(in []byte) (interface{}, []byte, error) {
		return parseType(in)
	}
	tests := []parseTest {
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
	runParseTests(t, tests, fn)
}

func TestParseLength(t *testing.T) {
	fn := func(in []byte) (interface{}, []byte, error) {
		return parseLength(in)
	}
	tests := []parseTest {
		{[]byte{0x81, 0x01}, true, tlvLength{1, false}},
		{[]byte{0x82, 0x01, 0x00}, true, tlvLength{256, false}},
		{[]byte{0x80}, true, tlvLength{0, true}},
		{[]byte{}, false, tlvLength{}},
		{[]byte{0x83, 0x01, 0x00}, false, tlvLength{}},
		{[]byte{0xff}, false, tlvLength{}},
	}
	runParseTests(t, tests, fn)
}

