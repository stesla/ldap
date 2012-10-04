package asn1

const ( // ASN.1 Classes
	ClassUniversal   = 0 // 0b00
	ClassApplication = 1 // 0b01
	ClassContextSpecific     = 2 // 0b10
	ClassPrivate     = 3 // 0b11
)

const ( // ASN.1 Universal Tags
	// TagEndOfContent     = 0x00
	TagBoolean          = 0x01
	TagInteger          = 0x02
	// TagBitString        = 0x03
	TagOctetString      = 0x04
	TagNull             = 0x05
	// TagObjectIdentifier = 0x06
	// TagObjectDescriptor = 0x07
	// TagExternal         = 0x08
	// TagReal             = 0x09
	TagEnumerated       = 0x0a
	// TagEmbeddedPDV      = 0x0b
	// TagUTF8String       = 0x0c
	// TagRelativeOID      = 0x0d
	TagSequence         = 0x10
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
	isCompound bool
}

func parseMetadata(in []byte) (out metadata, rem []byte, err error) {
	rem = in[:]
	if len(rem) == 0 {
		err = IncompleteTLVError{"no identifier byte"}
		return
	}
	var md metadata
	md.class = int(rem[0] >> 6)
	md.isCompound = rem[0] & 0x20 == 0x20

	if tag := rem[0] & 0x1f; tag < 0x1f {
		md.tag = int(tag)
	} else {
		for {
			if rem = rem[1:]; len(rem) == 0 {
				err = IncompleteTLVError{"long-form tag"}
				return
			}
			md.tag = (md.tag << 7) + int(rem[0] & 0x1f)
			if rem[0] & 0x80 == 0 {
				break
			}
		}
	}
	rem = rem[1:]

	if len(rem) == 0 {
		err = IncompleteTLVError{"no length byte"}
		return
	}

	if length := rem[0]; length < 0x80 {
		md.length = int(length)
	} else if length == 0x80 {
		md.length = -1
	} else if length == 0xff {
		err = SyntaxError{"long-form length"}
		return
	} else {
		i := length & 0x7f
		for ; i > 0; i-- {
			rem = rem[1:]
			if len(rem) == 0 {
				err = IncompleteTLVError{"long-form length"}
				return
			}
			md.length = (md.length << 8) + int(rem[0])
		}
	}

	out = md
	return
}
