package ldap

import (
	"crypto/tls"
	"testing"

	"gopkg.in/stretchr/testify.v1/assert"
)

func TestDialAndBind(t *testing.T) {
	var tlsConfig = tls.Config{
		InsecureSkipVerify: true,
	}
	var tests = []struct {
		addr string
		fn   func(string) (Conn, error)
	}{
		{"localhost:389", Dial},
		{"localhost:636", func(addr string) (Conn, error) {
			return DialSSL(addr, &tlsConfig)
		}},
		{"localhost:389", func(addr string) (Conn, error) {
			return DialTLS(addr, &tlsConfig)
		}},
	}

	for _, test := range tests {
		func() {
			conn, err := test.fn(test.addr)
			if !assert.NoError(t, err, "error connecting to %v", test.addr) {
				return
			}
			defer conn.Close()
			err = conn.Bind("cn=Alice Lastname,ou=users,dc=example,dc=org", "password")
			if !assert.NoError(t, err, "error binding") {
				return
			}
			err = conn.Unbind()
			assert.NoError(t, err, "error unbinding")
		}()
	}
}
