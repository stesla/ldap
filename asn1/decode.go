package asn1

import (
	"io"
	"reflect"
)

type tlvType struct {
	class, tag int
	isCompound bool
}

type tlvLength struct {
	length       int
	isIndefinite bool
}

func decodeType(r io.Reader, buf []byte) (out tlvType, err error) {
	_, err = r.Read(buf[0:1])
	if err != nil {
		return
	}

	out.class = int(buf[0] >> 6)
	out.isCompound = buf[0]&0x20 == 0x20

	if tag := buf[0] & 0x1f; tag < 0x1f {
		out.tag = int(tag)
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
			out.tag = out.tag<<7 | int(buf[0]&0x1f)

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

func decodeLength(r io.Reader, buf []byte) (out tlvLength, err error) {
	_, err = r.Read(buf[0:1])
	if err != nil {
		return
	}

	if length := buf[0]; length < 0x80 {
		out.length = int(length)
	} else if length == 0x80 {
		out.isIndefinite = true
	} else if length == 0xff {
		err = SyntaxError{"long-form length"}
		return
	} else {
		var width int
		n := length & 0x7f
		width, err = io.ReadFull(r, buf[0:n])
		if err != nil {
			return
		}
		for _, b := range buf[0:width] {
			out.length = out.length<<8 | int(b)
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

func (dec *Decoder) Decode(out interface{}) error {
	v := reflect.ValueOf(out).Elem()
	if v.Type() != rawValueType {
		return StructuralError{"Unsupported Type"}
	}

	buf := make([]byte, 10)

	t, err := decodeType(dec.r, buf)
	if err != nil {
		return err
	}

	l, err := decodeLength(dec.r, buf)
	if err != nil {
		return err
	}

	var b []byte
	if l.isIndefinite {
		b = make([]byte, 2)
		_, err = io.ReadFull(dec.r, b)
		if err != nil {
			return err
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
				return err
			}
		}
	} else {
		b = make([]byte, l.length)
		_, err = io.ReadFull(dec.r, b)
		if err != nil {
			return err
		}
	}

	result := RawValue{t.class, t.tag, b}
	v.Set(reflect.ValueOf(result))
	return nil
}
