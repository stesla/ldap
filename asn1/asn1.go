package asn1

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

type StructuralError struct {
	Msg string
}

func (e StructuralError) Error() string { return "ASN.1 Structural Error: " + e.Msg }

type SyntaxError struct {
	Msg string
}

func (e SyntaxError) Error() string { return "ASN.1 Syntax Error: " + e.Msg }

type RawValue struct {
	Class, Tag    int
	IsConstructed bool
	Bytes         []byte
}
