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
	isConstructed bool
}

func sliceDecoderFn(fn func(*Decoder) (interface{}, error)) decodeFn {
	return func(in interface{}) (interface{}, error) {
		r := bytes.NewReader(in.([]byte))
		dec := NewDecoder(r)
		return fn(dec)
	}
}

func TestDecodeType(t *testing.T) {
	fn := sliceDecoderFn(func (dec *Decoder) (interface{}, error) {
		class, tag, isConstructed, err := dec.decodeType()
		if err != nil {
			return nil, err
		}
		return tlvType{class, tag, isConstructed}, nil
	})
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
	fn := sliceDecoderFn(func (dec *Decoder) (interface{}, error) {
		length, isIndefinite, err := dec.decodeLength()
		if err != nil {
			return nil, err
		}
		return tlvLength{length, isIndefinite}, nil
	})
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

func decodeValueFn(out interface{}) decodeFn {
	return sliceDecoderFn(func (dec *Decoder) (interface{}, error) {
		err := dec.Decode(out)
		return reflect.ValueOf(out).Elem().Interface(), err
	})
}

func TestDecodeRawValue(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x05, 0x00}, true, RawValue{0, 5, false, []byte{}}},
		{[]byte{0x04, 0x03, 'f', 'o', 'o'}, true, RawValue{0, 4, false, []byte("foo")}},
		{[]byte{0x04, 0x80, 0x00, 0x00}, true, RawValue{0, 4, false, []byte{}}},
		{[]byte{0x04, 0x80, 'b', 'a', 'r', 0x00, 0x00}, true,
			RawValue{0, 4, false, []byte("bar")}},
	}
	var out RawValue
	runDecoderTests(t, tests, decodeValueFn(&out))
}

func TestDecodeBool(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x01, 0x01, 0x00}, true, false},
		{[]byte{0x01, 0x01, 0x01}, true, true},
		{[]byte{0x01, 0x01, 0xff}, true, true},
		{[]byte{0x01, 0x00}, false, nil},
		{[]byte{0x01, 0x02, 0x00, 0x01}, false, nil},
	}
	var out bool
	runDecoderTests(t, tests, decodeValueFn(&out))
}

func TestDecodeByteSlice(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x04, 0x00}, true, []byte{}},
		{[]byte{0x04, 0x03, 'f', 'o', 'o'}, true, []byte("foo")},
	}
	var out []byte
	runDecoderTests(t, tests, decodeValueFn(&out))
}

func TestDecodeNull(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x05, 0x00}, true, Null{}},
		{[]byte{0x05, 0x01, 0x01}, false, nil},
	}
	var out Null
	runDecoderTests(t, tests, decodeValueFn(&out))
}

func TestDecodeInt64(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x02, 0x01, 0x00}, true, int64(0)},
		{[]byte{0x02, 0x01, 0x2a}, true, int64(42)},
		{[]byte{0x02, 0x02, 0x12, 0x34}, true, int64(0x1234)},
		{[]byte{0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01}, true, int64(0x100000001)},
	}
	var out int64
	runDecoderTests(t, tests, decodeValueFn(&out))
}

func TestDecodeInt(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x02, 0x01, 0x00}, true, int(0)},
		{[]byte{0x02, 0x01, 0x2a}, true, int(42)},
		{[]byte{0x02, 0x02, 0x12, 0x34}, true, int(0x1234)},
		{[]byte{0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01}, false, nil},
	}
	var out int
	runDecoderTests(t, tests, decodeValueFn(&out))
}

type checkTagTest struct {
	class, tag int
	primitive  bool
	val        interface{}
	ok         bool
}

func TestCheckTag(t *testing.T) {
	tests := []checkTagTest{
		{ClassUniversal, TagNull, false, Null{}, true},
		{ClassUniversal, TagBoolean, false, true, true},
		{ClassUniversal, TagInteger, false, int(0), true},
		{ClassUniversal, TagInteger, false, int32(0), true},
		{ClassUniversal, TagInteger, false, int64(0), true},
		{ClassUniversal, TagOctetString, false, []byte{}, true},
		{ClassApplication, TagNull, false, 0, false},
		{ClassContextSpecific, TagNull, false, 0, false},
		{ClassPrivate, TagNull, false, 0, false},
		{ClassUniversal, TagNull, true, 0, false},
		{ClassUniversal, TagBoolean, true, 0, false},
		{ClassUniversal, TagInteger, true, 0, false},
		{ClassUniversal, TagOctetString, true, 0, false}, // TODO
	}
	for i, test := range tests {
		err := checkTag(test.class, test.tag, test.primitive, reflect.ValueOf(test.val))
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (passed? %v, expected %v): %s",
				i, err == nil, test.ok, err)
		}
	}
}
