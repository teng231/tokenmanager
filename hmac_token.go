package tokenmanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

// Mgr create method for working jwt
type HMACToken struct {
	secret string
}

// CreateHMACToken is parse pub, priv key then init HMACToken
func CreateHMACToken(secret string) (*HMACToken, error) {
	mgr := &HMACToken{}
	if secret == "" {
		return nil, errors.New(E_not_found_secret)
	}
	mgr.secret = secret
	return mgr, nil
}

// SetSecret is push privatekey to Helper
func (t *HMACToken) SetSecret(path string) error {
	secBin, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	t.secret = string(secBin)
	return err
}

// GenerateHmacToken is create token with secret
func (t *HMACToken) GenerateHmacToken(payload interface{}, duration time.Duration) (string, error) {
	//  make header use algorithm HS 256
	claims := jwt.MapClaims{}
	bin, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(bin, &claims); err != nil {
		return "", err
	}
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["iat"] = time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(t.secret))
}

// ParseHmacToken is verify token string is valid: input is secret
func (t *HMACToken) ParseHmacToken(tk string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tk, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(t.secret), nil
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
		return nil, errors.New(E_token_invalid_not_found)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New(E_claims_not_valid)
	}
	return claims, nil
}
