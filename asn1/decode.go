package asn1

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
)

type Decoder struct {
	Implicit bool
	r        io.Reader
	b        []byte
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r: r,
		// 10 bytes ought to be long enough for any tag or length
		b: make([]byte, 1, 10),
	}
}

func (dec *Decoder) Read(out []byte) (int, error) {
	return dec.r.Read(out)
}

func (dec *Decoder) Decode(out interface{}) error {
	return dec.DecodeWithOptions(out, "")
}

func (dec *Decoder) DecodeWithOptions(out interface{}, options string) error {
	opts := parseFieldOptions(options)
	v := reflect.ValueOf(out).Elem()
	return dec.decodeField(v, opts)
}

var (
	rawValueType = reflect.TypeOf(RawValue{})
	EOC          = fmt.Errorf("End-Of-Content")
)

func (dec *Decoder) decodeField(v reflect.Value, opts fieldOptions) (err error) {
	class, tag, constructed, err := dec.decodeType()
	if err != nil {
		return
	}

	if class == 0x00 && tag == 0x00 {
		_, err = dec.Read(dec.b[:1])
		if err != nil {
			return err
		} else if l := dec.b[0]; l != 0x00 {
			return SyntaxError(fmt.Sprintf("End-Of-Content tag with non-zero length byte %#x", l))
		}
		return EOC
	}

	for {
		if k := v.Kind(); k == reflect.Ptr || k == reflect.Interface {
			v = v.Elem()
		} else {
			break
		}
	}

	if !v.IsValid() {
		return StructuralError("IsValid = false")
	} else if !v.CanSet() {
		return StructuralError("CanSet = false")
	}

	if v.Type() == rawValueType {
		raw := RawValue{Class: class, Tag: tag, Constructed: constructed}
		raw.Bytes, err = dec.decodeLengthAndContent()
		if err != nil {
			return
		}
		v.Set(reflect.ValueOf(raw))
		return
	}

	err = dec.checkTag(class, tag, constructed, opts, v)
	if err != nil {
		return
	}

	if constructed {
		return dec.decodeConstructed(v, opts)
	}
	return dec.decodePrimitive(v)
}

func (dec *Decoder) decodeConstructed(v reflect.Value, opts fieldOptions) (err error) {
	length, indefinite, err := dec.decodeLength()
	if err != nil {
		return
	}

	if !indefinite {
		b, err := dec.decodeContent(length, indefinite)
		if err != nil {
			return err
		}
		defer func(r io.Reader) {
			dec.r = r
		}(dec.r)
		b = append(b, 0x00, 0x00)
		dec.r = bytes.NewReader(b)
	}

	if opts.tag != nil && (opts.implicit == nil || !*opts.implicit) {
		err = dec.decodeField(v, fieldOptions{})
		if err != nil {
			return
		}
		return dec.decodeEndOfContent()
	}

	switch v.Kind() {
	case reflect.Slice:
		return dec.decodeSequenceSlice(v)
	case reflect.Struct:
		return dec.decodeSequenceStruct(v)
	}
	return StructuralError(fmt.Sprintf("Unsupported Type: %v", v.Type()))
}

func (dec *Decoder) decodeSequenceSlice(v reflect.Value) (err error) {
	t := v.Type().Elem()
	v.Set(reflect.MakeSlice(v.Type(), 0, 0))
	for ok := true; ok; {
		vv := reflect.New(t).Elem()
		err = dec.decodeField(vv, fieldOptions{})
		if err == EOC {
			err = nil
			break
		} else if err != nil {
			return
		}
		v.Set(reflect.Append(v, vv))
	}
	return
}

func (dec *Decoder) decodeSequenceStruct(v reflect.Value) (err error) {
	max := v.NumField()
	for i := 0; i < max; i++ {
		vv := v.Field(i)
		vt := v.Type().Field(i)
		opts := parseFieldOptions(vt.Tag.Get("asn1"))
		err = dec.decodeField(vv, opts)
		if err != nil {
			return
		}
	}
	err = dec.decodeEndOfContent()
	return
}

func (dec *Decoder) decodeEndOfContent() (err error) {
	err = dec.decodeField(reflect.ValueOf(&RawValue{}).Elem(), fieldOptions{})
	if err == EOC {
		err = nil
	} else if err == nil {
		err = StructuralError("ran out of struct fields before end-of-content")
	}
	return
}

func (dec *Decoder) decodePrimitive(v reflect.Value) (err error) {
	b, err := dec.decodeLengthAndContent()
	if err != nil {
		return
	}
	switch v.Kind() {
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return decodeByteSlice(b, v)
		}
	case reflect.Bool:
		return decodeBool(b, v)
	case reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8, reflect.Int:
		return decodeInteger(b, v)
	}
	return StructuralError(fmt.Sprintf("Unsupported Type: %v", v.Type()))
}

func (dec *Decoder) decodeType() (class, tag int, constructed bool, err error) {
	dec.b = dec.b[:1]
	_, err = io.ReadFull(dec, dec.b)
	if err != nil {
		return
	}

	class = int(dec.b[0] >> 6)
	constructed = dec.b[0]&0x20 == 0x20

	if c := dec.b[0] & 0x1f; c < 0x1f {
		tag = int(c)
	} else {
		dec.b = dec.b[:len(dec.b)+1]
		_, err = io.ReadFull(dec, dec.b[len(dec.b)-1:len(dec.b)])
		if err != nil {
			return
		}

		if dec.b[len(dec.b)-1]&0x7f == 0 {
			err = SyntaxError("long-form tag")
			return
		}

		for {
			tag = tag<<7 | int(dec.b[len(dec.b)-1]&0x1f)
			if dec.b[len(dec.b)-1]&0x80 == 0 {
				break
			}

			dec.b = dec.b[:len(dec.b)+1]
			_, err = io.ReadFull(dec, dec.b[len(dec.b)-1:len(dec.b)])
			if err != nil {
				return
			}
		}
	}
	return
}

func (dec *Decoder) decodeLengthAndContent() (b []byte, err error) {
	length, indefinite, err := dec.decodeLength()
	if err != nil {
		return
	}
	return dec.decodeContent(length, indefinite)
}

func (dec *Decoder) decodeContent(length int, indefinite bool) (b []byte, err error) {
	if indefinite {
		b = make([]byte, 2)
		_, err = io.ReadFull(dec, b)
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
			_, err = dec.Read(b[len(b)-1:])
			if err != nil {
				return
			}
		}
	} else {
		b = make([]byte, length)
		_, err = io.ReadFull(dec, b)
		if err != nil {
			return
		}
	}
	return
}

func (dec *Decoder) decodeLength() (length int, isIndefinite bool, err error) {
	_, err = dec.Read(dec.b[0:1])
	if err != nil {
		return
	}

	if c := dec.b[0]; c < 0x80 {
		length = int(c)
	} else if c == 0x80 {
		isIndefinite = true
	} else if c == 0xff {
		err = SyntaxError("long-form length")
		return
	} else {
		var width int
		n := c & 0x7f
		width, err = io.ReadFull(dec, dec.b[0:n])
		if err != nil {
			return
		}
		for _, b := range dec.b[0:width] {
			length = length<<8 | int(b)
		}
	}
	return
}

func (dec *Decoder) checkTag(class, tag int, constructed bool, opts fieldOptions, v reflect.Value) (err error) {
	var ok bool

	if opts.tag != nil {
		ok = tag == *opts.tag &&
			((opts.implicit != nil && *opts.implicit) || dec.Implicit || constructed) &&
			((opts.application && class == ClassApplication) || class == ClassContextSpecific)
	} else if class == ClassUniversal {
		switch tag {
		case TagBoolean:
			ok = !constructed && v.Kind() == reflect.Bool
		case TagOctetString:
			ok = !constructed && v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8
		case TagInteger, TagEnumerated:
			ok = !constructed && reflect.Int <= v.Kind() && v.Kind() <= reflect.Int64
		case TagSequence:
			okKind := v.Kind() == reflect.Slice || v.Kind() == reflect.Struct
			ok = constructed && okKind
		}
	}

	if !ok {
		err = StructuralError(
			fmt.Sprintf("tag mismatch (class = %#x, tag = %#x, constructed = %t, type = %v)",
				class, tag, constructed, v.Type()))
	}

	return
}

func decodeBool(b []byte, v reflect.Value) error {
	if len(b) != 1 {
		return SyntaxError(fmt.Sprintf("booleans must be only one byte (len = %d)", len(b)))
	}
	v.SetBool(b[0] != 0)
	return nil
}

func decodeByteSlice(b []byte, v reflect.Value) (err error) {
	v.SetBytes(b)
	return
}

func decodeInteger(b []byte, v reflect.Value) error {
	if len(b) == 0 {
		return SyntaxError("integer must have at least one byte of content")
	}

	var i int64
	for _, b := range b {
		i = i<<8 + int64(b)
	}

	if v.OverflowInt(i) {
		return StructuralError("integer overflow")
	}

	v.SetInt(i)

	return nil
}
