package vault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	hvault "github.com/hashicorp/vault/api"
)

// Token - vault token information
type Token struct {
	token, token_file string
	expires           time.Time
	mutex             sync.Mutex
}

// NewToken - creates a new instance of Token
func NewToken(token string) (t *Token) {
	return &Token{
		token: token,
	}
}

// SetToken - sets a token
func (t *Token) SetToken(token string) {
	t.token = token
}

// SetTokenFile - sets a file to read the token from
func (t *Token) SetTokenFile(token_file string) (err error) {
	t.token_file = token_file
	return
}

// GetToken - returns the token
func (t *Token) GetToken(c *hvault.Client) (token string, err error) {

	t.mutex.Lock()
	defer t.mutex.Unlock()

	// prefer token file over configured token, since an external app can write the token without us needing to worry about renewal and expiry
	if len(t.token_file) != 0 {
		bytes, err := ioutil.ReadFile(t.token_file)
		if nil != err {
			return "", fmt.Errorf("gettoken: %w", err)
		}

		return string(bytes), nil
	}

	// if the token lifetime has not epired, return it
	if time.Now().UTC().Before(t.expires) {
		return t.token, nil
	}

	// this is run only the first time this function is called, after which we will have the information populated
	if t.expires.IsZero() {
		c.SetToken(t.token)
		secret, errZero := c.Logical().Read("/auth/token/lookup-self")
		if nil != errZero {
			return "", fmt.Errorf("gettoken: %w", errZero)
		}
		//print.JSON(secret)

		ttl, errZero := secret.Data["creation_ttl"].(json.Number).Int64()
		if nil != errZero {
			return "", fmt.Errorf("gettoken: %w", errZero)
		}

		if ttl > 20 {
			ttl -= 10 // we reduce the ttl to give a chance for this library to renew the token
		}

		if nil != secret.Data["expire_time"] {
			tm, _ := time.Parse("2006-01-02T15:04:05.000000000Z", secret.Data["expire_time"].(string))
			t.expires = tm.Add(time.Duration(ttl) * time.Second).UTC()
		} else {
			// if there is no expiry, we set one far into the future
			t.expires = time.Now().UTC().AddDate(1000, 0, 0)
		}

		return t.token, nil
	}

	// try to renew the token
	c.SetToken(t.token)
	_, err = c.Logical().Write("/auth/token/renew-self", nil)
	if nil != err {
		return "", fmt.Errorf("gettoken: %w", err)
	}

	return t.token, nil
}
