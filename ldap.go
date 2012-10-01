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

func (l *conn) Bind(user, password string) error {
	bindRequest, err := marshalComponents(
		ldapVersion,
		asn1.RawValue{Class: 0, Tag: 4, Bytes: []byte(user)},
		asn1.RawValue{Class: 2, Tag: 0, Bytes: []byte(password)})
	if err != nil {
		return err
	}
	err = l.writeMessage(ldapBindRequest, bindRequest)
	if err != nil {
		return err
	}

	//TODO: extract the rest of this into some sort of function
	buf := make([]byte, 4096)
	_, err = l.Read(buf)
	if err != nil {
		return err
	}

	var msg ldapMessage
	_, err = asn1.Unmarshal(buf, &msg)
	if err != nil {
		return err
	}

	var resp asn1.RawValue
	_, err = asn1.Unmarshal(msg.Op.FullBytes, &resp)
	if err != nil {
		return err
	}

	if resp.Class != classApplication || resp.Class != ldapBindResponse {
		return LDAPError{"response tag mismatch"}
	}

	var resultCode asn1.Enumerated
	_, err = asn1.Unmarshal(resp.Bytes, &resultCode)
	if err != nil {
		return err
	}

	if resultCode != ldapSuccess {
		return LDAPError{fmt.Sprintf("bind resultCode = %d", resultCode)}
	}
	return nil
}
