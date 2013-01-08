package asn1

import (
	"bytes"
	"reflect"
	"testing"
)

type encoderTest struct {
	in  interface{}
	ok  bool
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
		{RawValue{Class: 0, Tag: 5, Constructed: false, Bytes: []byte{}}, true, []byte{0x05, 0x00}},
		{RawValue{Class: 0, Tag: 4, Constructed: false, Bytes: []byte("foo")}, true, []byte{0x04, 0x03, 'f', 'o', 'o'}},
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
		{namedPoint{point{6, 7}, []byte("bar")}, true,
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

func TestEncodeIndirectly(t *testing.T) {
	a, b := 4, 2
	tests := []encoderTest{
		{ipoint{&a, &b}, true, []byte{0x30, 0x06, 0x02, 0x01, 0x04, 0x02, 0x01, 0x02}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeTags(t *testing.T) {
	tests := []encoderTest{
		{OptionValue{"tag:1,implicit", true}, true, []byte{0x81, 0x01, 0xff}},
		{OptionValue{"tag:2,implicit,application", true}, true, []byte{0x42, 0x01, 0xff}},
		{OptionValue{"tag:3,explicit", true}, true, []byte{0xa3, 0x03, 0x01, 0x01, 0xff}},
		{OptionValue{"tag:4", true}, true, []byte{0xa4, 0x03, 0x01, 0x01, 0xff}},
	}
	runEncoderTests(t, tests)
}

func TestImplicitEncoder(t *testing.T) {
	var out bytes.Buffer
	enc := NewEncoder(&out)
	enc.Implicit = true
	err := enc.Encode(OptionValue{"tag:1", true})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	expected := []byte{0x81, 0x01, 0xff}
	actual := out.Bytes()
	if err == nil && !reflect.DeepEqual(expected, actual) {
		t.Errorf("Bad result: %v (expected %v)", actual, expected)
	}
}

func TestEncodeTaggedStructFields(t *testing.T) {
	tests := []encoderTest{
		{tpoint{6, 7}, true, []byte{0x30, 0x06, 0x80, 0x01, 0x06, 0x81, 0x01, 0x07}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeOptionalStructFields(t *testing.T) {
	tests := []encoderTest{
		{opoint{6, 7}, true, []byte{0x30, 0x06, 0x02, 0x01, 0x06, 0x80, 0x01, 0x07}},
		{opoint{X: 16}, true, []byte{0x30, 0x03, 0x02, 0x01, 0x10}},
		{opoint{Y: 32}, true, []byte{0x30, 0x03, 0x80, 0x01, 0x20}},
		{opoint{}, true, []byte{0x30, 0x00}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeSet(t *testing.T) {
	tests := []encoderTest{
		{OptionValue{"set", []int{}}, true, []byte{0x31, 0x00}},
		{OptionValue{"set", []int{6, 7}}, true, []byte{0x31, 0x06, 0x02, 0x01, 0x06, 0x02, 0x01, 0x07}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeComponentsOf(t *testing.T) {
	tests := []encoderTest{
		{line{point{1, 2}, point{3, 4}}, true,
			[]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04}},
	}
	runEncoderTests(t, tests)
}

func TestEncodeLongLength(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	err := enc.Encode(RawValue{Bytes: make([]byte, 128)})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// We know the tag gets encoded right, so we won't look at that,
	// we'll just look at the length and one byte after.
	expected := []byte{0x81, 0x80, 0}
	actual := buf.Bytes()[1:4]
	if err == nil && !reflect.DeepEqual(expected, actual) {
		t.Errorf("Bad result: %v (expected %v)", actual, expected)
	}
}
