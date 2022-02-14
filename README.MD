# Tokenmanager
Control flow token generate and parse token.

[![Go](https://github.com/teng231/tokenmanager/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/teng231/tokenmanager/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/princjef/gomarkdoc.svg)](https://pkg.go.dev/github.com/teng231/tokenmanager)

## Installing and Usage

```bash
go get github.com/teng231/tokenmanager
```
struct of claims example:
```json
{
  "exp": 1632109978,
  "iat": 1632108178,
  "payload": {
    "user_id": 1,
    "role_id": 0
  }
}
```

all data store in payload.

### Alg RSA

Gen demo rsa keygen
```bash
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
# Don't add passphrase
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
cat jwtRS256.key
cat jwtRS256.key.pub
```
* Genkey
```go
func GenKey() {
	mgr, err := CreateRSAToken("", "./test/jwtRS256.key")
	if err != nil {
		t.Fail()
	}
	tk, err := mgr.GenerateToken(Claims{UserId: 1}, 30*time.Minute)
	if err != nil {
		t.Fail()
	}
	log.Println(tk)
}

```

* Parse
```go
func ParseKey(tk string) {
	mgr, err := CreateRSAToken("./test/jwtRS256.key.pub", "")
	if err != nil {
		t.Fail()
	}
	extractor, err := mgr.ParseToken(tk)
	if err != nil {
		t.Fail()
	}
	bin, err := json.Marshal(extractor["payload"])
	if err != nil {
		t.Fail()
	}
	claim := &Claims{}
	json.Unmarshal(bin, claim)
	log.Println(claim)
	if claim.UserId != 1 {
		t.Fail()
	}
}
```

### Alg HMAC

Hmac input need a secret path like: `./test/secret`

* Genkey

```go
func Genkey() {
	mgr, err := CreateHMACToken("./test/secret")
	if err != nil {
		t.Fail()
	}
	tk, err := mgr.GenerateHmacToken(Claims{UserId: 1}, 30*time.Second)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	log.Println(tk)
}
```

* ParseKey


```go
func Genkey(tk string) {
	mgr, err := CreateHMACToken("./test/secret")
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	extractor, err := mgr.ParseHmacToken(tk)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	bin, err := json.Marshal(extractor["payload"])
	if err != nil {
		t.Fail()
	}
	claim := &Claims{}
	json.Unmarshal(bin, claim)
	log.Println(claim)
	if claim.UserId != 1 {
		t.Fail()
	}
}
```
