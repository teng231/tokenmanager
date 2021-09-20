package tokenmanager

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

type RSAToken struct {
	publ *rsa.PublicKey
	priv *rsa.PrivateKey
}

// CreateRSAToken is parse pub, priv key then init RSAToken
func CreateRSAToken(pub, priv string) (*RSAToken, error) {
	mgr := &RSAToken{}
	if pub != "" {
		if err := mgr.SetPublicKey(pub); err != nil {
			log.Print(err)
			return nil, err
		}
	}
	if priv != "" {
		if err := mgr.SetPrivateKey(priv); err != nil {
			log.Print(err)
			return nil, err
		}
	}
	return mgr, nil
}

// SetPublicKey push publickey to Helper
func (t *RSAToken) SetPublicKey(path string) error {
	publPerm, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	// log.Println("public", string(publPerm))
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publPerm)
	t.publ = publicKey
	return err
}

// SetPrivateKey is push privatekey to Helper
func (t *RSAToken) SetPrivateKey(path string) error {
	privPerm, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	// log.Println("private", string(privPerm))
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPerm)
	t.priv = privateKey
	return err
}

// GenerateToken is create token with privatekey
func (t *RSAToken) GenerateToken(payload interface{}, duration time.Duration) (string, error) {
	//  make header use algorithm RSA 256
	token := jwt.New(jwt.SigningMethodRS256)
	// make payload
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["iat"] = time.Now().Unix()
	claims["payload"] = payload
	token.Claims = claims
	return token.SignedString(t.priv)
}

// ParseToken is verify token string is valid: input is public key
func (t *RSAToken) ParseToken(tk string) (map[string]interface{}, error) {
	log.Print(t)
	token, err := jwt.Parse(tk, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("alg is %v", token.Header["alg"])
		}
		return t.publ, nil
	})
	switch err.(type) {
	case nil: // no error
		if !token.Valid { // but may still be invalid
			return nil, errors.New(E_token_invalid)
		}
	case *jwt.ValidationError: // something was wrong during the validation
		vErr := err.(*jwt.ValidationError)
		switch vErr.Errors {
		case jwt.ValidationErrorExpired:
			return nil, errors.New(E_token_expired)
		default:
			return nil, errors.New(E_token_fail_to_valid)
		}
	default: // something else went wrong
		return nil, errors.New(E_token_invalid)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New(E_claims_not_valid)
	}
	return claims, nil
}
