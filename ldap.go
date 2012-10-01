package ldap

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"net"
)

type Conn interface {
	net.Conn
	Bind(user, password string) error
	Unbind() error
}

// TODO: Implement TLS
func Dial(addr string) (Conn, error) {
	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newConn(tcp), nil
}

type conn struct {
	net.Conn
	nextId int
}

func newConn(tcp net.Conn) *conn {
	return &conn{tcp, 0}
}

func (l *conn) getNextId() (id int) {
	//TODO: add a mutex around this
	id = l.nextId
	l.nextId++
	return
}
type ldapMessage struct {
	ID int
	Op asn1.RawValue
	Controls asn1.RawValue `asn1:"optional,tag:0"`
}

func marshalComponents(components ...interface{}) ([]byte, error) {
	var buf bytes.Buffer
	for _, c := range components {
		b, err := asn1.Marshal(c)
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(b)
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (l *conn) writeMessage(tag int, op []byte) error {
	var msg ldapMessage
	msg.ID = l.getNextId()
	msg.Op = asn1.RawValue{Class: 1, Tag: tag, IsCompound: true, Bytes: op}
	b, err := asn1.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = l.Write(b)
	return err
}

func (l *conn) readResponse(tag int) (out []byte, err error) {
	buf := make([]byte, 4096)

	_, err = l.Read(buf)
	if err != nil {
		return
	}

	var msg ldapMessage
	_, err = asn1.Unmarshal(buf, &msg)
	if err != nil {
		return
	}

	var resp asn1.RawValue
	_, err = asn1.Unmarshal(msg.Op.FullBytes, &resp)
	if err != nil {
		return
	}

	if !(resp.Class == classApplication && resp.Tag == tag) {
		return nil, LDAPError{"response tag mismatch"}
	}

	return resp.Bytes, nil
}

func (l *conn) Bind(user, password string) error {
	bindRequest, err := marshalComponents(
		ldapVersion,
		asn1.RawValue{Class: classUniversal, Tag: tagOctetString, Bytes: []byte(user)},
		asn1.RawValue{Class: classContext, Tag: 0, Bytes: []byte(password)})
	if err != nil {
		return err
	}
	err = l.writeMessage(ldapBindRequest, bindRequest)
	if err != nil {
		return err
	}

	respBytes, err := l.readResponse(ldapBindResponse)
	if err != nil {
		return err
	}

	var resultCode asn1.Enumerated
	_, err = asn1.Unmarshal(respBytes, &resultCode)
	if err != nil {
		return err
	}

	if resultCode != ldapSuccess {
		return LDAPError{fmt.Sprintf("bind resultCode = %d", resultCode)}
	}
	return nil
}

func (l *conn) Unbind() error {
	null, err := asn1.Marshal(asn1.RawValue{Class: classUniversal, Tag: tagNull})
	if err != nil {
		return err
	}
	err = l.writeMessage(ldapUnbindRequest, null)
	if err != nil {
		return err
	}
	return nil
}
