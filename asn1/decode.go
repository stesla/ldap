package asn1

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
)

var EOC = fmt.Errorf("End-Of-Content")

type Decoder struct {
	Implicit bool
	r        io.Reader
	b        []byte
	typeb    []byte
	lenb     []byte
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r: r,
		b: make([]byte, 0, 10),
		// 10 bytes ought to be long enough for any tag or length
		typeb: make([]byte, 1, 10),
		lenb:  make([]byte, 1, 10),
	}
}

func (dec *Decoder) Read(out []byte) (n int, err error) {
	if len(dec.b) > 0 {
		n = copy(out, dec.b)
		dec.b = dec.b[n:]
	}
	if n < len(out) {
		var nn int
		nn, err = dec.r.Read(out[n:])
		n += nn
	}
	return
}

func (dec *Decoder) Decode(out interface{}) error {
	v := reflect.Indirect(reflect.ValueOf(out))
	return dec.decodeField(v, fieldOptions{})
}

func (dec *Decoder) decodeField(v reflect.Value, opts fieldOptions) (err error) {
	class, tag, constructed, err := dec.decodeType()
	if err != nil {
		return
	}

	if class == 0x00 && tag == 0x00 {
		_, err = dec.Read(dec.lenb[:1])
		if err != nil {
			return err
		} else if l := dec.lenb[0]; l != 0x00 {
			return SyntaxError(fmt.Sprintf("End-Of-Content tag with non-zero length byte %#x", l))
		}
		return EOC
	}

	v, opts = dereference(v, opts)

	if !v.IsValid() {
		return StructuralError("IsValid = false")
	} else if !v.CanSet() {
		return StructuralError("CanSet = false")
	}

	if v.Type() == rawValueType {
		return dec.decodeRawValue(v, class, tag, constructed)
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

func (dec *Decoder) decodeRawValue(v reflect.Value, class, tag int, constructed bool) error {
	raw := RawValue{Class: class, Tag: tag, Constructed: constructed}

	bs, indefinite, err := dec.decodeLengthAndContent()
	if err != nil {
		return err
	}
	raw.Bytes = bs

	var buf bytes.Buffer
	buf.Write(dec.typeb)
	buf.Write(dec.lenb)
	buf.Write(raw.Bytes)
	if indefinite {
		buf.Write([]byte{0, 0})
	}
	raw.RawBytes = buf.Bytes()

	v.Set(reflect.ValueOf(raw))
	return nil
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

	if opts.tag != nil && (opts.implicit == nil || !*opts.implicit) && !dec.Implicit {
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
		if err = dec.decodeSequenceStruct(v); err != nil {
			return err
		} else {
			return dec.decodeEndOfContent()
		}
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
		vv, opts = dereference(vv, opts)
		if opts.components && vv.Kind() == reflect.Struct {
			err = dec.decodeSequenceStruct(vv)
		} else {
			err = dec.decodeField(vv, opts)
		}
		if err != nil {
			if !opts.optional {
				return
			}
			if err == EOC {
				dec.b = append(dec.b, 0x00, 0x00)
			} else {
				n := copy(dec.b[:cap(dec.b)], dec.typeb)
				dec.b = dec.b[:n]
			}
			err = nil
		}
	}
	return
}

func (dec *Decoder) decodeEndOfContent() (err error) {
	err = dec.decodeField(reflect.ValueOf(&RawValue{}).Elem(), fieldOptions{})
	if err == EOC {
		err = nil
	} else if err == nil {
		err = StructuralError("ran out of data locations before end-of-content")
	}
	return
}

func (dec *Decoder) decodePrimitive(v reflect.Value) (err error) {
	b, _, err := dec.decodeLengthAndContent()
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
	dec.typeb = dec.typeb[:1]
	_, err = io.ReadFull(dec, dec.typeb)
	if err != nil {
		return
	}

	class = int(dec.typeb[0] >> 6)
	constructed = dec.typeb[0]&0x20 == 0x20

	if c := dec.typeb[0] & 0x1f; c < 0x1f {
		tag = int(c)
	} else {
		dec.typeb = dec.typeb[:len(dec.typeb)+1]
		_, err = io.ReadFull(dec, dec.typeb[len(dec.typeb)-1:len(dec.typeb)])
		if err != nil {
			return
		}

		if dec.typeb[len(dec.typeb)-1]&0x7f == 0 {
			err = SyntaxError("long-form tag")
			return
		}

		for {
			tag = tag<<7 | int(dec.typeb[len(dec.typeb)-1]&0x1f)
			if dec.typeb[len(dec.typeb)-1]&0x80 == 0 {
				break
			}

			dec.typeb = dec.typeb[:len(dec.typeb)+1]
			_, err = io.ReadFull(dec, dec.typeb[len(dec.typeb)-1:len(dec.typeb)])
			if err != nil {
				return
			}
		}
	}
	return
}

func (dec *Decoder) decodeLengthAndContent() (b []byte, indefinite bool, err error) {
	length, indefinite, err := dec.decodeLength()
	if err != nil {
		return
	}
	b, err = dec.decodeContent(length, indefinite)
	return
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
	_, err = dec.Read(dec.lenb[0:1])
	if err != nil {
		return
	}

	if c := dec.lenb[0]; c < 0x80 {
		length = int(c)
	} else if c == 0x80 {
		isIndefinite = true
	} else if c == 0xff {
		err = SyntaxError("long-form length")
		return
	} else {
		width := c & 0x7f
		dec.lenb = dec.lenb[:1+width]
		_, err = io.ReadFull(dec, dec.lenb[1:1+width])
		if err != nil {
			return
		}
		for _, b := range dec.lenb[1 : 1+width] {
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
		case TagSet, TagSequence:
			okKind := v.Kind() == reflect.Slice || v.Kind() == reflect.Struct
			ok = constructed && okKind && (opts.set || tag == TagSequence)
		default:
			ok = false
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
