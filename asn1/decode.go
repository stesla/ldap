package asn1

import (
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
	rawValueType = reflect.TypeOf(RawValue{})
)

func (dec *Decoder) Decode(out interface{}) (err error) {
	raw, err := dec.decodeRawValue()
	if err != nil {
		return
	}

	switch v := reflect.ValueOf(out).Elem(); v.Type() {
	case rawValueType:
		v.Set(reflect.ValueOf(raw))
	default:
		err = StructuralError{"Unsupported Type"}
	}
	return
}

func (dec *Decoder) decodeRawValue() (out RawValue, err error) {
	buf := make([]byte, 10)

	out.Class, out.Tag, out.IsCompound, err = decodeType(dec.r, buf)
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
