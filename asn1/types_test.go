package asn1

type tlvType struct {
	class, tag    int
	isConstructed bool
}

type tlvLength struct {
	length       int
	isIndefinite bool
}

type point struct {
	X, Y int
}

type namedPoint struct {
	Point point
	Name  []byte
}

type ipoint struct {
	X, Y interface{}
}

type tpoint struct {
	X int `asn1:"tag:0,implicit"`
	Y int `asn1:"tag:1,implicit"`
}

type opoint struct {
	X int `asn1:"optional"`
	Y int `asn1:"tag:0,implicit,optional"`
}

type outer struct {
	Inner interface{}
}

type inner struct {
	Enum MyEnum
}

type line struct {
	A point `asn1:"components"`
	B point `asn1:"components"`
}
