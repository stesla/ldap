package asn1

import (
	"reflect"
	"testing"
)

type parseMetadataTest struct {
	in []byte
	ok bool
	out metadata
}

var parseMetadataTests = []parseMetadataTest{
	// Good Input
	{[]byte{0x00, 0x00}, true, metadata{0, 0, 0, false}},
	{[]byte{0x80, 0x01}, true, metadata{2, 0, 1, false}},
	{[]byte{0xa0, 0x01}, true, metadata{2, 0, 1, true}},
	{[]byte{0x41, 0x01}, true, metadata{1, 1, 1, false}},
	{[]byte{0xfe, 0x00}, true, metadata{3, 30, 0, true}},
	{[]byte{0x1f, 0x01, 0x00}, true, metadata{0, 1, 0, false}},
	{[]byte{0x1f, 0x81, 0x00, 0x00}, true, metadata{0, 128, 0, false}},
	{[]byte{0x1f, 0x81, 0x80, 0x01, 0x00}, true, metadata{0, 0x4001, 0, false}},
	{[]byte{0x00, 0x81, 0x01}, true, metadata{0, 0, 1, false}},
	{[]byte{0x00, 0x82, 0x01, 0x00}, true, metadata{0, 0, 256, false}},
	{[]byte{0x30, 0x80}, true, metadata{0, 16, -1, true}},
	// Errors
	{[]byte{}, false, metadata{}},
	{[]byte{0x00}, false, metadata{}},
	{[]byte{0x00, 0x83, 0x01, 0x00}, false, metadata{}},
	{[]byte{0x1f, 0x85}, false, metadata{}},
	{[]byte{0x00, 0xff}, false, metadata{}},
}

func TestParseMetadata(t *testing.T) {
	for i, test := range parseMetadataTests {
		metadata, _, err := parseMetadata(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (actual = %v, expected = %v)",
				i, err == nil, test.ok)
		}
		if err == nil && !reflect.DeepEqual(test.out, metadata) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, metadata, test.out)
		}
	}
}
