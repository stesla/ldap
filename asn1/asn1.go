package asn1

import (
	"io"
)

const ( // ASN.1 Classes
	ClassUniversal       = 0 // 0b00
	ClassApplication     = 1 // 0b01
	ClassContextSpecific = 2 // 0b10
	ClassPrivate         = 3 // 0b11
)

const ( // ASN.1 Universal Tags
	// TagEndOfContent     = 0x00
	TagBoolean = 0x01
	TagInteger = 0x02
	// TagBitString        = 0x03
	TagOctetString = 0x04
	TagNull        = 0x05
	// TagObjectIdentifier = 0x06
	// TagObjectDescriptor = 0x07
	// TagExternal         = 0x08
	// TagReal             = 0x09
	TagEnumerated = 0x0a
	// TagEmbeddedPDV      = 0x0b
	// TagUTF8String       = 0x0c
	// TagRelativeOID      = 0x0d
	TagSequence = 0x10
	// TagSet              = 0x11
	// TagNumericString    = 0x12
	// TagPrintableString  = 0x13
	// TagT61String        = 0x14
	// TagVideotexString   = 0x15
	// TagIA5String        = 0x16
	// TagUTCTime          = 0x17
	// TagGeneralizedTime  = 0x18
	// TagGraphicString    = 0x19
	// TagVisibleString    = 0x1a
	// TagGeneralString    = 0x1b
	// TagUniversalString  = 0x1c
	// TagCharacterString  = 0x1d
	// TagBMPString        = 0x1e
)

type IncompleteTLVError struct {
	Msg string
}

func (e IncompleteTLVError) Error() string { return "ASN.1 Incomplete TLV: " + e.Msg }

type SyntaxError struct {
	Msg string
}

func (e SyntaxError) Error() string { return "ASN.1 Syntax Error: " + e.Msg }

type metadata struct {
	class, tag, length int
	isCompound         bool
}

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
		for {
			_, err = r.Read(buf[0:1])
			if err != nil {
				return
			}
			out.tag = out.tag<<7 | int(buf[0]&0x1f)
			if buf[0]&0x80 == 0 {
				break
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
