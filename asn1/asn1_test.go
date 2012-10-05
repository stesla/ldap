package asn1

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

type decodeTest struct {
	in  []byte
	ok  bool
	out interface{}
}

type decodeFn func(io.Reader, []byte) (interface{}, error)

func runDecodeTests(t *testing.T, tests []decodeTest, decode decodeFn) {
	buf := make([]byte, 8)
	for i, test := range tests {
		out, err := decode(bytes.NewReader(test.in), buf)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (passed? %v, expected %v)",
				i, err == nil, test.ok)
		}
		if err == nil && !reflect.DeepEqual(test.out, out) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, out, test.out)
		}
	}
}

func TestDecodeType(t *testing.T) {
	fn := func(r io.Reader, buf []byte) (interface{}, error) {
		return decodeType(r, buf)
	}
	tests := []decodeTest{
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
	runDecodeTests(t, tests, fn)
}

func TestDecodeLength(t *testing.T) {
	fn := func(r io.Reader, buf []byte) (interface{}, error) {
		return decodeLength(r, buf)
	}
	tests := []decodeTest{
		{[]byte{0x81, 0x01}, true, tlvLength{1, false}},
		{[]byte{0x82, 0x01, 0x00}, true, tlvLength{256, false}},
		{[]byte{0x80}, true, tlvLength{0, true}},
		{[]byte{}, false, tlvLength{}},
		{[]byte{0x83, 0x01, 0x00}, false, tlvLength{}},
		{[]byte{0xff}, false, tlvLength{}},
	}
	runDecodeTests(t, tests, fn)
}
