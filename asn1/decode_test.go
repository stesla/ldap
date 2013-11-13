package asn1

import (
	"bytes"
	"reflect"
	"testing"
)

type decoderTest struct {
	in  []byte
	ok  bool
	out interface{}
}

type decodeFn func(int, []byte) (interface{}, error)

func runDecoderTests(t *testing.T, tests []decoderTest, decode decodeFn) {
	for i, test := range tests {
		out, err := decode(i, test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (passed? %v, expected %v): %s",
				i, err == nil, test.ok, err)
		}
		if err == nil && !reflect.DeepEqual(test.out, out) {
			t.Errorf("#%d: Bad result: %v %v (expected %v %v)",
				i, reflect.TypeOf(out), out, reflect.TypeOf(test.out), test.out)
		}
	}
}

func withDecoder(fn func(int, *Decoder) (interface{}, error)) decodeFn {
	return func(i int, in []byte) (interface{}, error) {
		r := bytes.NewReader(in)
		dec := NewDecoder(r)
		return fn(i, dec)
	}
}

func withInitialValue(out interface{}, fn func(i int, dec *Decoder) error) decodeFn {
	v := reflect.Indirect(reflect.ValueOf(out))
	orig := v.Interface()
	return withDecoder(func(i int, dec *Decoder) (interface{}, error) {
		if v.IsValid() && v.CanSet() {
			v.Set(reflect.ValueOf(orig))
		}
		err := fn(i, dec)
		return v.Interface(), err
	})
}

func withValue(out interface{}) decodeFn {
	return withInitialValue(out, func(i int, dec *Decoder) error {
		return dec.Decode(out)
	})
}

func withValueOptions(out interface{}, opts map[int]string) decodeFn {
	return withInitialValue(out, func(i int, dec *Decoder) error {
		return dec.Decode(OptionValue{opts[i], out})
	})
}

func TestDecodeType(t *testing.T) {
	fn := withDecoder(func(i int, dec *Decoder) (interface{}, error) {
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

func TestDecodeLength(t *testing.T) {
	fn := withDecoder(func(i int, dec *Decoder) (interface{}, error) {
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

func TestDecodeRawValue(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x05, 0x00}, true, RawValue{0, 5, false, []byte{}, []byte{0x05, 0x00}}},
		{[]byte{0x04, 0x03, 'f', 'o', 'o'}, true, RawValue{0, 4, false, []byte("foo"), []byte{0x04, 0x03, 'f', 'o', 'o'}}},
		{[]byte{0x04, 0x84, 0, 0, 0, 0x03, 'f', 'o', 'o'}, true,
			RawValue{0, 4, false, []byte("foo"), []byte{0x04, 0x84, 0, 0, 0, 0x03, 'f', 'o', 'o'}}},
		{[]byte{0x04, 0x80, 0x00, 0x00}, true, RawValue{0, 4, false, []byte{}, []byte{0x04, 0x80, 0x00, 0x00}}},
		{[]byte{0x04, 0x80, 'b', 'a', 'r', 0x00, 0x00}, true,
			RawValue{0, 4, false, []byte("bar"), []byte{0x04, 0x80, 'b', 'a', 'r', 0x00, 0x00}}},
	}
	var out RawValue
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeBool(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x01, 0x01, 0x00}, true, false},
		{[]byte{0x01, 0x01, 0x01}, true, true},
		{[]byte{0x01, 0x01, 0xff}, true, true},
		{[]byte{0x01, 0x00}, false, nil},
		{[]byte{0x01, 0x02, 0x00, 0x01}, false, nil},
		{[]byte{0x21, 0x01, 0x00}, false, nil},
	}
	var out bool
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeByteSlice(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x04, 0x00}, true, []byte{}},
		{[]byte{0x04, 0x03, 'f', 'o', 'o'}, true, []byte("foo")},
		// TODO: Support constructed octet strings
		{[]byte{0x24, 0x01, 0x00}, false, nil},
	}
	var out []byte
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeInt64(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x02, 0x01, 0x00}, true, int64(0)},
		{[]byte{0x02, 0x01, 0x2a}, true, int64(42)},
		{[]byte{0x02, 0x02, 0x12, 0x34}, true, int64(0x1234)},
		{[]byte{0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01}, true, int64(0x100000001)},
		{[]byte{0x22, 0x01, 0x00}, false, nil},
		{[]byte{0x22, 0x00}, false, nil},
	}
	var out int64
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeInt32(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x02, 0x01, 0x00}, true, int32(0)},
		{[]byte{0x02, 0x01, 0x2a}, true, int32(42)},
		{[]byte{0x02, 0x02, 0x12, 0x34}, true, int32(0x1234)},
		{[]byte{0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01}, false, nil},
		{[]byte{0x22, 0x01, 0x00}, false, nil},
		{[]byte{0x22, 0x00}, false, nil},
	}
	var out int32
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeInt16(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x02, 0x01, 0x00}, true, int16(0)},
		{[]byte{0x02, 0x01, 0x2a}, true, int16(42)},
		{[]byte{0x02, 0x02, 0x12, 0x34}, true, int16(0x1234)},
		{[]byte{0x02, 0x03, 0x01, 0x00, 0x01}, false, nil},
		{[]byte{0x22, 0x01, 0x00}, false, nil},
		{[]byte{0x22, 0x00}, false, nil},
	}
	var out int16
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeInt8(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x02, 0x01, 0x00}, true, int8(0)},
		{[]byte{0x02, 0x01, 0x2a}, true, int8(42)},
		{[]byte{0x02, 0x02, 0x01, 0x01}, false, nil},
		{[]byte{0x22, 0x01, 0x00}, false, nil},
		{[]byte{0x22, 0x00}, false, nil},
	}
	var out int8
	runDecoderTests(t, tests, withValue(&out))
}

type MyEnum int8

func TestDecodeEnumerated(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x0a, 0x01, 0x01}, true, MyEnum(1)},
		{[]byte{0x0a, 0x02, 0x01, 0x01}, false, nil},
		{[]byte{0x2a, 0x01, 0x00}, false, nil},
		{[]byte{0x2a, 0x00}, false, nil},
	}
	var out MyEnum
	runDecoderTests(t, tests, withValue(&out))
}

func TestOtherDecoderErrors(t *testing.T) {
	tests := []decoderTest{
		// TODO: support ClassPrivate
		{[]byte{0xc5, 0x01, 0x01}, false, int(1)},
	}
	var out int
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeSequenceSlice(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x30, 0x00}, true, []bool{}},
		{[]byte{0x30, 0x80, 0x00, 0x00}, true, []bool{}},
		{[]byte{0x30, 0x06, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01}, true, []bool{false, true}},
		{[]byte{0x30, 0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00}, true, []bool{true, false}},
		{[]byte{0x30, 0x80}, false, nil},
		{[]byte{0x30, 0x03, 0x02, 0x01, 0x00}, false, nil},
	}
	var out []bool
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeNestedSequenceSlice(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x30, 0x00}, true, [][]bool{}},
		{[]byte{0x30, 0x80,
			0x30, 0x03, 0x01, 0x01, 0x00,
			0x30, 0x03, 0x01, 0x01, 0x01,
			0x00, 0x00}, true, [][]bool{[]bool{false}, []bool{true}}},
	}
	var out [][]bool
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeSequenceStruct(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x30, 0x0d,
			0x30, 0x06, 0x02, 0x01, 0x06, 0x02, 0x01, 0x07, // point{6, 7}
			0x04, 0x03, 'f', 'o', 'o',
		}, true, namedPoint{point{6, 7}, []byte("foo")}},
		{[]byte{0x30, 0x80,
			0x30, 0x06, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x18, // point{42, 24}
			0x04, 0x03, 'b', 'a', 'r',
			0x00, 0x00,
		}, true, namedPoint{point{42, 24}, []byte("bar")}},
		{[]byte{0x30, 0x80,
			0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		}, false, nil},
		{[]byte{0x30, 0x80,
			0x04, 0x01, 'x',
		}, false, nil},
		{[]byte{0x30, 0x80,
			0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
			0x04, 0x01, 'x',
		}, false, nil},
		{[]byte{0x30, 0x80,
			0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
			0x04, 0x01, 'x',
			0x01, 0x01, 0x01,
			0x00, 0x00,
		}, false, nil},
		{[]byte{0x30, 0x0e,
			0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
			0x04, 0x01, 'x',
			0x01, 0x01, 0x01,
		}, false, nil},
	}
	var out namedPoint
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeWithExtraIndirection(t *testing.T) {
	a, b := 4, 2
	test := []decoderTest{
		{[]byte{0x30, 0x06, 0x02, 0x01, 0x04, 0x02, 0x01, 0x02}, true, ipoint{&a, &b}},
	}
	out := ipoint{new(int), new(int)}
	runDecoderTests(t, test, withValue(&out))
}

func TestDecodeTagging(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x01, 0x01, 0x01}, true, true},
		{[]byte{0x81, 0x01, 0x00}, true, false},
		{[]byte{0x42, 0x01, 0x01}, true, true},
		{[]byte{0xA3, 0x03, 0x01, 0x01, 0x00}, true, false},
		{[]byte{0xA4, 0x03, 0x01, 0x01, 0x01}, true, true},
		{[]byte{0x85, 0x01, 0x00}, false, false},
	}
	opts := map[int]string{
		1: "tag:1,implicit",
		2: "tag:2,implicit,application",
		3: "tag:3,explicit",
		4: "tag:4",
		5: "tag:5",
		6: "tag:1,application",
	}
	var out bool
	runDecoderTests(t, tests, withValueOptions(&out, opts))
}

func TestImplicitDecoder(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte{0x81, 0x01, 0x01}))
	dec.Implicit = true
	var out bool
	err := dec.Decode(OptionValue{"tag:1", &out})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if err == nil && !out {
		t.Errorf("Bad value: %v (expected %v)", out, true)
	}
}

func TestDecodeTaggedStructFields(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x30, 0x06, 0x80, 0x01, 0x06, 0x81, 0x01, 0x07}, true, tpoint{6, 7}},
		{[]byte{0x30, 0x06, 0x02, 0x01, 0x06, 0x02, 0x01, 0x07}, false, nil},
	}
	var out tpoint
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeOptionalStructFields(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x30, 0x06, 0x02, 0x01, 0x06, 0x80, 0x01, 0x07}, true, opoint{6, 7}},
		{[]byte{0x30, 0x03, 0x02, 0x01, 0x10}, true, opoint{X: 16}},
		{[]byte{0x30, 0x03, 0x80, 0x01, 0x20}, true, opoint{Y: 32}},
		{[]byte{0x30, 0x00}, true, opoint{}},
	}
	out := opoint{}
	runDecoderTests(t, tests, withValue(&out))
}

func TestDecodeIndirectOptions(t *testing.T) {
	a, b := 4, 2
	test := []decoderTest{
		{[]byte{0x30, 0x06, 0x80, 0x01, 0x04, 0x81, 0x01, 0x02}, true,
			ipoint{
				OptionValue{"tag:0,implicit", &a},
				OptionValue{"tag:1,implicit", &b}}},
	}
	out := ipoint{
		OptionValue{"tag:0,implicit", new(int)},
		OptionValue{"tag:1,implicit", new(int)},
	}
	runDecoderTests(t, test, withValue(&out))
}

func TestDecodeStructOptionStruct(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte{0x30, 0x05, 0x61, 0x03, 0x0a, 0x01, 0x2a}))
	dec.Implicit = true
	out := outer{OptionValue{"application,tag:1", new(inner)}}
	err := dec.Decode(&out)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if err == nil && out.Inner.(OptionValue).Value.(*inner).Enum != MyEnum(42) {
		t.Errorf("Bad value: %v (expected %v)", out, true)
	}
}

func TestDecodeSet(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x31, 0x00}, true, []int{}},
		{[]byte{0x31, 0x06, 0x02, 0x01, 0x06, 0x02, 0x01, 0x07}, true, []int{6, 7}},
	}
	opts := map[int]string{
		0: "set",
		1: "set",
	}
	var out []int
	runDecoderTests(t, tests, withValueOptions(&out, opts))
}

func TestDecodeComponentsOf(t *testing.T) {
	tests := []decoderTest{
		{[]byte{0x30, 0xc, 0x2, 0x1, 0x1, 0x2, 0x1, 0x2, 0x2, 0x1, 0x3, 0x2, 0x1, 0x4}, true,
			line{point{1, 2}, point{3, 4}}},
		{[]byte{0x30, 0x9, 0x2, 0x1, 0x1, 0x2, 0x1, 0x2, 0x2, 0x1, 0x3, 0x2, 0x1, 0x4}, false, line{}},
		{[]byte{0x30, 0xf, 0x2, 0x1, 0x1, 0x2, 0x1, 0x2, 0x2, 0x1, 0x3, 0x2, 0x1, 0x4, 0x2, 0x1, 0x5}, false, line{}},
	}
	var out line
	runDecoderTests(t, tests, withValue(&out))
}
