package asn1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

type Encoder struct {
	Implicit bool
	b        *bytes.Buffer
	w        io.Writer
	ww       io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	buf := new(bytes.Buffer)
	return &Encoder{
		b:  buf,
		w:  buf,
		ww: w,
	}
}

func (enc *Encoder) Encode(in interface{}) (err error) {
	v := reflect.Indirect(reflect.ValueOf(in))
	if err = enc.encodeField(v, fieldOptions{}); err != nil {
		return
	}
	_, err = enc.b.WriteTo(enc.ww)
	return
}

func (enc *Encoder) encodeField(v reflect.Value, opts fieldOptions) (err error) {
	v, opts = dereference(v, opts)

	if opts.optional && reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface()) {
		return
	}

	if opts.tag != nil && !(opts.implicit != nil && *opts.implicit) && !enc.Implicit {
		v = reflect.ValueOf([]interface{}{v.Interface()})
	}

	if err = enc.encodeType(v, opts); err != nil {
		return
	}

	buf, err := enc.encodeContent(v)
	if err != nil {
		return
	}

	if !opts.components {
		if err = enc.encodeLength(buf.Len()); err != nil {
			return
		}
	}

	_, err = buf.WriteTo(enc.w)
	return
}

func (enc *Encoder) encodeType(v reflect.Value, opts fieldOptions) (err error) {
	var class, tag int
	var constructed bool

	t := v.Type()
	switch t {
	case rawValueType:
		raw := v.Interface().(RawValue)
		class, tag, constructed = raw.Class, raw.Tag, raw.Constructed
	default:
		switch t.Kind() {
		case reflect.Bool:
			tag = TagBoolean
		case reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8, reflect.Int:
			if opts.enum {
				tag = TagEnumerated
			} else {
				tag = TagInteger
			}
		case reflect.Slice:
			if opts.set {
				tag, constructed = TagSet, true
			} else if t.Elem().Kind() == reflect.Uint8 {
				tag = TagOctetString
			} else {
				tag, constructed = TagSequence, true
			}
		case reflect.Struct:
			tag, constructed = TagSequence, true
		default:
			err = fmt.Errorf("Type not supported: %v", v.Type())
		}
	}

	if opts.components && constructed {
		return
	} else if opts.components {
		return fmt.Errorf("Cannot encode COMPONENTS OF primitive value")
	}

	if err != nil {
		return
	}

	if opts.tag != nil {
		tag = *opts.tag

		if opts.application {
			class = ClassApplication
		} else {
			class = ClassContextSpecific
		}
	}

	ident := uint8(class<<6 + tag)
	if constructed {
		ident += 0x20
	}
	_, err = enc.w.Write([]byte{ident})
	return
}

func (enc *Encoder) encodeLength(length int) (err error) {
	var bs []byte

	if bs, err = encodeInt64(int64(length)); err != nil {
		return err
	}

	if len(bs) > 1 || bs[0]&0x80 == 0x80 {
		if _, err = enc.w.Write([]byte{uint8(0x80 | len(bs))}); err != nil {
			return err
		}
	}

	_, err = enc.w.Write(bs)
	return err
}

func (enc *Encoder) encodeContent(v reflect.Value) (buf bytes.Buffer, err error) {
	t := v.Type()
	switch t {
	case rawValueType:
		buf.Write(v.FieldByName("Bytes").Bytes())
	default:
		switch t.Kind() {
		case reflect.Bool:
			if v.Bool() {
				buf.WriteByte(0xff)
			} else {
				buf.WriteByte(0x00)
			}
		case reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8, reflect.Int:
			var bs []byte
			bs, err = encodeInt64(v.Int())
			if err != nil {
				return
			}
			buf.Write(bs)
		case reflect.Slice:
			if t.Elem().Kind() == reflect.Uint8 {
				buf.Write(v.Bytes())
			} else {
				defer func(w io.Writer) {
					enc.w = w
				}(enc.w)
				enc.w = &buf
				for i := 0; i < v.Len(); i++ {
					if err = enc.encodeField(v.Index(i), fieldOptions{}); err != nil {
						return
					}
				}
			}
		case reflect.Struct:
			defer func(w io.Writer) {
				enc.w = w
			}(enc.w)
			enc.w = &buf
			for i := 0; i < v.NumField(); i++ {
				vv := v.Field(i)
				opts := parseFieldOptions(v.Type().Field(i).Tag.Get("asn1"))
				if err = enc.encodeField(vv, opts); err != nil {
					return
				}
			}
		}
	}
	return
}

func encodeInt64(i int64) ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, i)
	if err != nil {
		return nil, err
	}
	// binary.Write always writes out all 8 bytes for an int64. On
	// the other hand, DER-encoding requires we use the shortest
	// possible encoding. So, we trim off all the leading
	// zeroes. If the last byte in the slice is a zero, then we
	// must be encoding the number zero, so we leave it.
	bs := buf.Bytes()
	for len(bs) > 1 && bs[0] == 0 {
		bs = bs[1:]
	}
	return bs, nil
}
