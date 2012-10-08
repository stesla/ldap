package asn1

import (
	"fmt"
	"io"
	"reflect"
)

func decodeType(r io.Reader, buf []byte) (class, tag int, isCompound bool, err error) {
	_, err = r.Read(buf[0:1])
	if err != nil {
		return
	}

	class = int(buf[0] >> 6)
	isCompound = buf[0]&0x20 == 0x20

	if c := buf[0] & 0x1f; c < 0x1f {
		tag = int(c)
	} else {
		_, err = r.Read(buf[0:1])
		if err != nil {
			return
		}

		if buf[0]&0x7f == 0 {
			err = SyntaxError{"long-form tag"}
			return
		}

		for {
			tag = tag<<7 | int(buf[0]&0x1f)

			if buf[0]&0x80 == 0 {
				break
			}

			_, err = r.Read(buf[0:1])
			if err != nil {
				return
			}
		}
	}
	return
}

func decodeLength(r io.Reader, buf []byte) (length int, isIndefinite bool, err error) {
	_, err = r.Read(buf[0:1])
	if err != nil {
		return
	}

	if c := buf[0]; c < 0x80 {
		length = int(c)
	} else if c == 0x80 {
		isIndefinite = true
	} else if c == 0xff {
		err = SyntaxError{"long-form length"}
		return
	} else {
		var width int
		n := c & 0x7f
		width, err = io.ReadFull(r, buf[0:n])
		if err != nil {
			return
		}
		for _, b := range buf[0:width] {
			length = length<<8 | int(b)
		}
	}
	return
}

type Decoder struct {
	r io.Reader
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r}
}

var (
	boolType     = reflect.TypeOf(true)
	byteSliceType = reflect.TypeOf([]byte{})
	enumeratedType = reflect.TypeOf(Enumerated(0))
	intType = reflect.TypeOf(int(0))
	int64Type = reflect.TypeOf(int64(0))
	nullType = reflect.TypeOf(Null{})
	rawValueType = reflect.TypeOf(RawValue{})
)

func (dec *Decoder) Decode(out interface{}) (err error) {
	raw, err := dec.decodeRawValue()
	if err != nil {
		return
	}

	v := reflect.ValueOf(out).Elem()
	result, err := decodeValue(raw, v.Type())
	if err == nil {
		v.Set(reflect.ValueOf(result))
	}
	return
}

func (dec *Decoder) decodeRawValue() (out RawValue, err error) {
	buf := make([]byte, 10)

	out.Class, out.Tag, out.IsConstructed, err = decodeType(dec.r, buf)
	if err != nil {
		return
	}

	length, isIndefinite, err := decodeLength(dec.r, buf)
	if err != nil {
		return
	}

	if isIndefinite {
		b := make([]byte, 2)
		_, err = io.ReadFull(dec.r, b)
		if err != nil {
			return
		}
		for {
			if b[len(b)-2] == 0 && b[len(b)-1] == 0 {
				b = b[:len(b)-2]
				break
			}
			if len(b) == cap(b) {
				bb := make([]byte, len(b), 2*len(b))
				copy(bb, b)
				b = bb
			}
			b = b[:len(b)+1]
			_, err = dec.r.Read(b[len(b)-1:])
			if err != nil {
				return
			}
		}
		out.Bytes = b
	} else {
		out.Bytes = make([]byte, length)
		_, err = io.ReadFull(dec.r, out.Bytes)
		if err != nil {
			return
		}
	}
	return
}

func decodeValue(raw RawValue, typ reflect.Type) (out interface{}, err error) {
	switch typ {
	case rawValueType:
		out = raw
	case boolType:
		out, err = decodeBool(raw)
	case byteSliceType:
		out, err = decodeByteSlice(raw)
	case enumeratedType:
		out, err = decodeEnumerated(raw)
	case intType:
		out, err = decodeInt(raw)
	case int64Type:
		out, err = decodeInt64(raw)
	case nullType:
		out, err = decodeNull(raw)
	default:
		err = StructuralError{fmt.Sprintf("Unsupported Type: %v", typ)}
	}
	return
}

func decodeBool(raw RawValue) (out interface{}, err error) {
	switch {
	case raw.Tag != TagBoolean && raw.Class == ClassUniversal:
		err = tagMismatch(raw)
	case raw.IsConstructed:
		err = SyntaxError{"booleans must be primitive"}
	case len(raw.Bytes) != 1:
		err = SyntaxError{fmt.Sprintf("booleans must be only one byte (len = %d)", len(raw.Bytes))}
	default:
		out = raw.Bytes[0] != 0
	}
	return
}

func decodeByteSlice(raw RawValue) (out interface{}, err error) {
	switch {
	case raw.Tag != TagOctetString && raw.Class == ClassUniversal:
		err = tagMismatch(raw)
	case raw.IsConstructed:
		err = SyntaxError{"constructed values are not supported"}
	default:
		b := make([]byte, len(raw.Bytes))
		copy(b, raw.Bytes)
		out = b
	}
	return
}

func tagMismatch(raw RawValue) error {
	return StructuralError{fmt.Sprintf("tag mismatch (class = %d, tag = %d)", raw.Class, raw.Tag)}
}

func decodeNull(raw RawValue) (out interface{}, err error) {
	switch {
	case raw.Tag != TagNull && raw.Class == ClassUniversal:
		err = tagMismatch(raw)
	case raw.IsConstructed:
		err = SyntaxError{"null must be primitive"}
	case len(raw.Bytes) != 0:
		err = SyntaxError{fmt.Sprintf("null must not have content (len = %d)", len(raw.Bytes))}
	default:
		out = Null{}
	}
	return
}

func decodeInt64(raw RawValue) (out interface{}, err error) {
	switch {
	case raw.Tag != TagInteger && raw.Class == ClassUniversal:
		err = tagMismatch(raw)
	case raw.IsConstructed:
		err = SyntaxError{"integer must be primitive"}
	case len(raw.Bytes) == 0:
		err = SyntaxError{"integer must have at least one byte of content"}
	default:
		var i int64
		for _, b := range raw.Bytes {
			i = i<<8 + int64(b)
		}
		out = i
	}
	return
}

func decodeInt(raw RawValue) (out interface{}, err error) {
	ret, err := decodeInt64(raw)
	if err != nil {
		return
	}
	ret64 := ret.(int64)
	if i := int(ret64); ret64 == int64(i) {
		out = i
	} else {
		err = StructuralError{"integer overflow"}
	}
	return
}

func decodeEnumerated(raw RawValue) (out interface{}, err error) {
	switch {
	case raw.Tag != TagEnumerated && raw.Class == ClassUniversal:
		err = tagMismatch(raw)
	case raw.IsConstructed:
		err = SyntaxError{"enumerated must be primitive"}
	case len(raw.Bytes) == 0:
		err = SyntaxError{"enumerated must have at least one byte of content"}
	default:
		var i int64
		for _, b := range raw.Bytes {
			i = i<<8 + int64(b)
		}
		if e := Enumerated(i); i == int64(e) {
			out = e
		} else {
			err = StructuralError{"integer overflow"}
		}
	}
	return
}
