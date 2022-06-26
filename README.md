# ldap

An LDAPv3 implementation for golang

## Running the Tests

Some of the tests expect there to be an LDAP server running on `localhost` with certain objects loaded. A [docker compose](docker-compose.yml) file has been provided along with the needed LDIF to populate it with the expected test data. So, to run the tests all you need to do is run this in one terminal:

```sh
$ docker-compose up
```

And then run this in another terminal:

```sh
$ go test ./...
```
