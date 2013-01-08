package ldap

import (
	"bytes"
	"fmt"
	"github.com/stesla/ldap/asn1"
	"net"
	"sync"
)

type Conn interface {
	net.Conn
	Bind(user, password string) error
	Unbind() error
	Search(req SearchRequest) ([]SearchResult, error)
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
	MessageId  int
	ProtocolOp interface{}
	Controls   []interface{} `asn1:"tag:0,optional"`
}

type ldapResultCode int16

const (
	Success                     ldapResultCode = 0
	InappropriateAuthentication ldapResultCode = 48
	InvalidCredentials          ldapResultCode = 49
	InsufficientAccessRights    ldapResultCode = 59
)

type ldapResult struct {
	ResultCode ldapResultCode
	MatchedDN  []byte
	Message    []byte
	Referral   []interface{} `asn1:"tag:3,optional"`
}

type bindRequest struct {
	Version int8
	Name    []byte
	Auth    interface{}
}

func (l *conn) Bind(user, password string) (err error) {
	msg := ldapMessage{
		MessageId: l.id.Next(),
		ProtocolOp: asn1.OptionValue{
			"application,tag:0",
			bindRequest{
				Version: 3,
				Name:    []byte(user),
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
				Tag:   asn1.TagNull,
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
	l    sync.Mutex
}

func (gen *sequence) Next() (id int) {
	gen.l.Lock()
	defer gen.l.Unlock()
	id = gen.next
	gen.next++
	return
}

type SearchRequest struct {
	BaseObject []byte
	Scope SearchScope `asn1:"enum"`
	Deref DerefAliases `asn1:"enum"`
	SizeLimit int
	TimeLimit int
	TypesOnly bool
	Filter
	Attributes [][]byte
}

type SearchScope int

const (
	BaseObject SearchScope = 0
	SingleLevel SearchScope = 1
	WholeSubtree SearchScope = 2
)

type DerefAliases int

const (
	NeverDerefAliases DerefAliases = 0
	DerefInSearching DerefAliases = 1
	DerefFindingBaseObj DerefAliases = 2
	DerefAlways DerefAliases = 3
)

type SearchResult struct {
	DN string
	Attributes map[string][]string
}

func (l *conn) Search(req SearchRequest) ([]SearchResult, error) {
	msg := ldapMessage{
		MessageId: l.id.Next(),
		ProtocolOp: asn1.OptionValue{"application,tag:3", req},
	}

	enc := asn1.NewEncoder(l)
	enc.Implicit = true
	if err := enc.Encode(msg); err != nil {
		return nil, fmt.Errorf("Encode: %v", err)
	}

	dec := asn1.NewDecoder(l)
	dec.Implicit = true

	results := []SearchResult{}

loop:
	for {
		var raw asn1.RawValue
		resp := ldapMessage{ProtocolOp: &raw}
		if err := dec.Decode(&resp); err != nil {
			return nil, fmt.Errorf("Decode Envelope: %v", err)
		}
		rdec := asn1.NewDecoder(bytes.NewBuffer(raw.RawBytes))
		rdec.Implicit = true
		switch raw.Tag {
		case 4:
			var r struct {
				Name []byte
				Attributes []struct {
					Type []byte
					Values [][]byte `asn1:"set"`
				}
			}
			if err := rdec.Decode(asn1.OptionValue{"application,tag:4", &r}); err != nil {
				return nil, fmt.Errorf("Decode SearchResult: %v", err)
			}
			result := SearchResult{string(r.Name), make(map[string][]string)}
			for _, a := range r.Attributes {
				vals := []string{}
				for _, v := range a.Values {
					vals = append(vals, string(v))
				}
				result.Attributes[string(a.Type)] = vals
			}
			results = append(results, result)
		case 5:	 // SearchResultDone
			var r ldapResult
			if err := rdec.Decode(asn1.OptionValue{"application,tag:5", &r}); err != nil {
				return nil, fmt.Errorf("Decode SearchResultDone: %v", err)
			}
			if r.ResultCode != Success {
				return nil, fmt.Errorf("ResultCode = %d", r.ResultCode)
			}
			break loop
		case 19: // SearchResultReference
			// TODO
		}
	}

	return results, nil
}
