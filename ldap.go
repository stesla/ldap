package ldap

import (
	// "bytes"
	"fmt"
	"net"
	"sync"
	"github.com/stesla/ldap/asn1"
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
	id sequence
}

func newConn(tcp net.Conn) *conn {
	return &conn{
		Conn: tcp,
	}
}

type ldapMessage struct {
	MessageId int
	ProtocolOp interface{}
	Controls []interface{} `asn1:"tag:0,optional"`
}

type ldapResultCode int16

const (
    Success ldapResultCode = 0
    SnappropriateAuthentication ldapResultCode = 48
    SnvalidCredentials ldapResultCode = 49
    SnsufficientAccessRights ldapResultCode = 59
)

type ldapResult struct {
	ResultCode ldapResultCode
	MatchedDN []byte
	Message []byte
	Referral []interface{} `asn1:"tag:3,optional"`
}

type bindRequest struct {
	Version int8
	Name []byte
	Auth interface{}
}

func (l *conn) Bind(user, password string) (err error) {
	msg := ldapMessage{
		MessageId: l.id.Next(),
		ProtocolOp: asn1.OptionValue{
			"application,tag:0",
			bindRequest{
				Version: 3,
				Name: []byte(user),
				// TODO: Support SASL
				Auth: simpleAuth(password),
			},
		},
	}

	enc := asn1.NewEncoder(l)
	enc.Implicit = true
	if err = enc.Encode(msg); err != nil {
		return fmt.Errorf("Encode: %v", err)
	}

	var result ldapResult
	msg = ldapMessage{
		ProtocolOp: asn1.OptionValue{"application,tag:1", &result},
	}
	dec := asn1.NewDecoder(l)
	dec.Implicit = true
	if err = dec.Decode(&msg); err != nil {
		return fmt.Errorf("Decode: %v", err)
	}

	if result.ResultCode != Success {
		return fmt.Errorf("ldap.Bind unsuccessful: resultCode = %v", result.ResultCode)
	}
	return nil
}

func simpleAuth(password string) interface{} {
	return asn1.OptionValue{"tag:0", []byte(password)}
}

func (l *conn) Unbind() error {
	defer l.Close()

	msg := ldapMessage{
		MessageId: l.id.Next(),
		ProtocolOp: asn1.OptionValue{
			"application,tag:2",
			asn1.RawValue{
				Class: asn1.ClassUniversal,
				Tag: asn1.TagNull,
			},
		},
	}

	enc := asn1.NewEncoder(l)
	enc.Implicit = true
	if err := enc.Encode(msg); err != nil {
		return fmt.Errorf("Encode: %v", err)
	}

	return nil
}

type sequence struct {
	next int
	l sync.Mutex
}

func (gen *sequence) Next() (id int) {
	gen.l.Lock()
	defer gen.l.Unlock()
	id = gen.next
	gen.next++
	return
}
