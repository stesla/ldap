package asn1

import (
	"bytes"
	"reflect"
	"testing"
)

type decoderTest struct {
	in  interface{}
	ok  bool
	out interface{}
}

type decodeFn func(interface{}) (interface{}, error)

func runDecoderTests(t *testing.T, tests []decoderTest, decode decodeFn) {
	for i, test := range tests {
		out, err := decode(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (passed? %v, expected %v): %s",
				i, err == nil, test.ok, err)
		}
		if err == nil && !reflect.DeepEqual(test.out, out) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, out, test.out)
		}
	}
}

type tlvType struct {
	class, tag int
	isCompound bool
}

func TestDecodeType(t *testing.T) {
	fn := func(in interface{}) (interface{}, error) {
		r := bytes.NewReader(in.([]byte))
		buf := make([]byte, 8)
		class, tag, isCompound, err := decodeType(r, buf)
		if err != nil {
			return nil, err
		}
		return tlvType{class, tag, isCompound}, nil
	}
	tests := []decoderTest{
		{[]byte{}, false, tlvType{}},
		{[]byte{0x1f, 0x85}, false, tlvType{}},
		{[]byte{0x1f, 0x00}, false, tlvType{}},
		{[]byte{0x00}, true, tlvType{0, 0, false}},
		{[]byte{0x80}, true, tlvType{2, 0, false}},
		{[]byte{0xa0}, true, tlvType{2, 0, true}},
		{[]byte{0x41}, true, tlvType{1, 1, false}},
		{[]byte{0xfe}, true, tlvType{3, 30, true}},
		{[]byte{0x1f, 0x01}, true, tlvType{0, 1, false}},
		{[]byte{0x1f, 0x81, 0x00}, true, tlvType{0, 128, false}},
		{[]byte{0x1f, 0x81, 0x80, 0x01}, true, tlvType{0, 0x4001, false}},
	}
	runDecoderTests(t, tests, fn)
}

type tlvLength struct {
	length       int
	isIndefinite bool
}

func TestDecodeLength(t *testing.T) {
	fn := func(in interface{}) (interface{}, error) {
		r := bytes.NewReader(in.([]byte))
		buf := make([]byte, 8)
		length, isIndefinite, err := decodeLength(r, buf)
		if err != nil {
			return nil, err
		}
		return tlvLength{length, isIndefinite}, nil
	}
	tests := []decoderTest{
		{[]byte{0x81, 0x01}, true, tlvLength{1, false}},
		{[]byte{0x82, 0x01, 0x00}, true, tlvLength{256, false}},
		{[]byte{0x80}, true, tlvLength{0, true}},
		{[]byte{}, false, tlvLength{}},
		{[]byte{0x83, 0x01, 0x00}, false, tlvLength{}},
		{[]byte{0xff}, false, tlvLength{}},
	}
	runDecoderTests(t, tests, fn)
}

func TestDecodeRawValue(t *testing.T) {
	fn := func(in interface{}) (interface{}, error) {
		r := bytes.NewReader(in.([]byte))
		dec := NewDecoder(r)
		out := RawValue{}
		err := dec.Decode(&out)
		return out, err
	}
	tests := []decoderTest{
		{[]byte{0x05, 0x00}, true, RawValue{0, 5, false, []byte{}}},
		{[]byte{0x04, 0x03, 'f', 'o', 'o'}, true, RawValue{0, 4, false, []byte("foo")}},
		{[]byte{0x04, 0x80, 0x00, 0x00}, true, RawValue{0, 4, false, []byte{}}},
		{[]byte{0x04, 0x80, 'b', 'a', 'r', 0x00, 0x00}, true,
			RawValue{0, 4, false, []byte("bar")}},
	}
	runDecoderTests(t, tests, fn)
}

func TestDecodeBool(t *testing.T) {
	fn := func(in interface{}) (interface{}, error) {
		raw := in.(RawValue)
		return decodeBool(raw)
	}
	tests := []decoderTest{
		{RawValue{ClassUniversal, TagBoolean, false, []byte{0x00}}, true, false},
		{RawValue{ClassUniversal, TagBoolean, false, []byte{0x01}}, true, true},
		{RawValue{ClassUniversal, TagBoolean, false, []byte{0xff}}, true, true},
		{RawValue{ClassUniversal, TagInteger, false, []byte{0xff}}, false, nil},
		{RawValue{ClassUniversal, TagBoolean, false, []byte{}}, false, nil},
		{RawValue{ClassUniversal, TagBoolean, false, []byte{0x00, 0x01}}, false, nil},
		{RawValue{ClassUniversal, TagBoolean, true, []byte{0x00}}, false, nil},
		{RawValue{ClassApplication, 1, false, []byte{0x00}}, true, false},
		{RawValue{ClassApplication, 2, false, []byte{0x01}}, true, true},
		{RawValue{ClassApplication, 3, false, []byte{0xff}}, true, true},
	}
	runDecoderTests(t, tests, fn)
}

func TestDecodeByteSlice(t *testing.T) {
	fn := func(in interface{}) (interface{}, error) {
		raw := in.(RawValue)
		return decodeByteSlice(raw)
	}
	tests := []decoderTest{
		{RawValue{ClassUniversal, TagOctetString, false, []byte{}}, true, []byte{}},
		{RawValue{ClassUniversal, TagOctetString, false, []byte("foo")}, true, []byte("foo")},
		{RawValue{ClassUniversal, TagBoolean, false, []byte{}}, false, nil},
		//TODO: constructed octet strings
		{RawValue{ClassUniversal, TagOctetString, true, []byte{}}, false, nil},
		{RawValue{ClassApplication, 1, false, []byte("bar")}, true, []byte("bar")},
	}
	runDecoderTests(t, tests, fn)
}
