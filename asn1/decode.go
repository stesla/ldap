package asn1

import (
	"fmt"
	"io"
	"reflect"
)

type Decoder struct {
	r   io.Reader
	buf []byte
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r: r,
		// 10 bytes ought to be long enough for any tag or length
		buf: make([]byte, 10),
	}
}

func (dec *Decoder) Decode(out interface{}) error {
	v := reflect.ValueOf(out).Elem()
	return dec.decodeField(v)
}

func (dec *Decoder) decodeField(v reflect.Value) (err error) {
	raw, err := dec.decodeRawValue()
	if err != nil {
		return
	}

	if v.Type() == rawValueType {
		v.Set(reflect.ValueOf(raw))
		return
	}

	err = checkTag(raw.Class, raw.Tag, raw.Constructed, v)
	if err != nil {
		return
	}

	return decodeValue(raw, v)
}

func (dec *Decoder) decodeRawValue() (out RawValue, err error) {
	out.Class, out.Tag, out.Constructed, err = dec.decodeType()
	if err != nil {
		return
	}

	length, isIndefinite, err := dec.decodeLength()
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

func (dec *Decoder) decodeType() (class, tag int, constructed bool, err error) {
	_, err = dec.r.Read(dec.buf[0:1])
	if err != nil {
		return
	}

	class = int(dec.buf[0] >> 6)
	constructed = dec.buf[0]&0x20 == 0x20

	if c := dec.buf[0] & 0x1f; c < 0x1f {
		tag = int(c)
	} else {
		_, err = dec.r.Read(dec.buf[0:1])
		if err != nil {
			return
		}

		if dec.buf[0]&0x7f == 0 {
			err = SyntaxError{"long-form tag"}
			return
		}

		for {
			tag = tag<<7 | int(dec.buf[0]&0x1f)

			if dec.buf[0]&0x80 == 0 {
				break
			}

			_, err = dec.r.Read(dec.buf[0:1])
			if err != nil {
				return
			}
		}
	}
	return
}

func (dec *Decoder) decodeLength() (length int, isIndefinite bool, err error) {
	_, err = dec.r.Read(dec.buf[0:1])
	if err != nil {
		return
	}

	if c := dec.buf[0]; c < 0x80 {
		length = int(c)
	} else if c == 0x80 {
		isIndefinite = true
	} else if c == 0xff {
		err = SyntaxError{"long-form length"}
		return
	} else {
		var width int
		n := c & 0x7f
		width, err = io.ReadFull(dec.r, dec.buf[0:n])
		if err != nil {
			return
		}
		for _, b := range dec.buf[0:width] {
			length = length<<8 | int(b)
		}
	}
	return
}

func checkTag(class, tag int, constructed bool, v reflect.Value) (err error) {
	var ok bool

	switch class {
	case ClassUniversal:
		switch tag {
		case TagBoolean:
			ok = !constructed && v.Kind() == reflect.Bool
		case TagOctetString:
			// TODO: ASN.1 supports constructed octet strings
			ok = !constructed && v.Type() == byteSliceType
		case TagInteger:
			k := v.Kind()
			ok = !constructed && (k == reflect.Int || k == reflect.Int32 || k == reflect.Int64)
		case TagNull:
			ok = !constructed && v.Type() == nullType
		}
	}

	if !ok {
		err = StructuralError{
			fmt.Sprintf("tag mismatch (class = %#x, tag = %#x, constructed = %t, type = %v)",
				class, tag, constructed, v.Type())}
	}

	return
}

var (
	byteSliceType = reflect.TypeOf([]byte{})
	nullType      = reflect.TypeOf(Null{})
	rawValueType  = reflect.TypeOf(RawValue{})
)

func decodeValue(raw RawValue, v reflect.Value) (err error) {
	switch v.Type() {
	case byteSliceType:
		return decodeByteSlice(raw, v)
	case nullType:
		return decodeNull(raw, v)
	}

	switch v.Kind() {
	case reflect.Bool:
		return decodeBool(raw, v)
	case reflect.Int64, reflect.Int32, reflect.Int:
		return decodeInteger(raw, v)
	}

	return StructuralError{fmt.Sprintf("Unsupported Type: %v", v.Type())}
}

func decodeBool(raw RawValue, v reflect.Value) error {
	if len(raw.Bytes) != 1 {
		return SyntaxError{fmt.Sprintf("booleans must be only one byte (len = %d)", len(raw.Bytes))}
	}
	v.SetBool(raw.Bytes[0] != 0)
	return nil
}

func decodeByteSlice(raw RawValue, v reflect.Value) (err error) {
	v.SetBytes(raw.Bytes)
	return
}

func decodeNull(raw RawValue, v reflect.Value) error {
	if len(raw.Bytes) != 0 {
		return SyntaxError{fmt.Sprintf("null must not have content (len = %d)", len(raw.Bytes))}
	}
	return nil
}

func decodeInteger(raw RawValue, v reflect.Value) error {
	if len(raw.Bytes) == 0 {
		return SyntaxError{"integer must have at least one byte of content"}
	}

	var i int64
	for _, b := range raw.Bytes {
		i = i<<8 + int64(b)
	}

	if v.OverflowInt(i) {
		return StructuralError{"integer overflow"}
	}

	v.SetInt(i)

	return nil
}
