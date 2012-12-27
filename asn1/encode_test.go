package asn1

import (
	"bytes"
	"reflect"
	"testing"
)

type encoderTest struct {
	in interface{}
	ok bool
	out []byte
}

func runEncoderTests(t *testing.T, tests []encoderTest) {
	for i, test := range tests {
		var out bytes.Buffer
		enc := NewEncoder(&out)
		err := enc.Encode(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (passed? %v, expected %v): %s",
				i, err == nil, test.ok, err)
		}
		if actual := out.Bytes(); err == nil && !reflect.DeepEqual(test.out, actual) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, actual, test.out)
		}
	}
}

func TestEncodeRawValue(t *testing.T) {
	tests := []encoderTest{
		// Raw Values
		{RawValue{0, 5, false, []byte{}}, true, []byte{0x05, 0x00}},
		{RawValue{0, 4, false, []byte("foo")}, true, []byte{0x04, 0x03, 'f', 'o', 'o'}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeBool(t *testing.T) {
	tests := []encoderTest{
		// Bool
		{false, true, []byte{0x01, 0x01, 0x00}},
		{true, true, []byte{0x01, 0x01, 0xff}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeInts(t *testing.T) {
	tests := []encoderTest{
		{int(0), true, []byte{0x02, 0x01, 0x00}},
		{int(42), true, []byte{0x02, 0x01, 0x2a}},
		{int(0x1234), true, []byte{0x02, 0x02, 0x12, 0x34}},
		{int8(1), true, []byte{0x02, 0x01, 0x01}},
		{int16(2), true, []byte{0x02, 0x01, 0x02}},
		{int32(3), true, []byte{0x02, 0x01, 0x03}},
		{int64(0x100000001), true, []byte{0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeSlice(t *testing.T) {
	tests := []encoderTest{
		{[]bool{}, true, []byte{0x30, 0x00}},
		{[]int{}, true, []byte{0x30, 0x00}},
		{[]bool{false, true}, true, []byte{0x30, 0x06, 0x01, 0x01, 0x00, 0x01, 0x01, 0xff}},
		{[]int{0x1234, 0x5678}, true, []byte{0x30, 0x08, 0x02, 0x02, 0x12, 0x34, 0x02, 0x02, 0x56, 0x78}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeByteSlice(t *testing.T) {
	tests := []encoderTest{
		{[]byte("foo"), true, []byte{0x04, 0x03, 'f', 'o', 'o'}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeSequenceStruct(t *testing.T) {
	tests := []encoderTest{
		{namedPoint{point{6,7}, []byte("bar")}, true,
			[]byte{0x30, 0x0d,
				0x30, 0x06, 0x02, 0x01, 0x06, 0x02, 0x01, 0x07, // point{6, 7}
				0x04, 0x03, 'b', 'a', 'r'}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeEnum(t *testing.T) {
	tests := []encoderTest{
		{OptionValue{"enum", MyEnum(6)}, true, []byte{0x0a, 0x01, 0x06}},
	}
	runEncoderTests(t, tests)
}
