package vault

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	hvault "github.com/hashicorp/vault/api"
)

// AppRolePath - default approle path
const AppRolePath = "approle"

// AppRole - vault AppRole information
type AppRole struct {
	appRoleName  string
	role_id      string
	secret_id    string
	unwrap_token string
	path         string
	auth         *hvault.SecretAuth
	expires      time.Time
	mutex        sync.Mutex
}

// NewAppRole - creates a new instance of AppRole
func NewAppRole(path, appRoleName, role_id string) (approle *AppRole) {
	return &AppRole{
		appRoleName: appRoleName,
		role_id:     role_id,
		path:        "auth/" + path,
	}
}

// SetSecretID - sets a secret id for a given AppRole for a configured `role_id`
func (ar *AppRole) SetSecretID(secret_id string) {
	ar.secret_id = secret_id
}

// SetUnwrapToken - sets an unwrap token to get the secret ID from vault for a configured `role_id`
func (ar *AppRole) SetUnwrapToken(unwrap_token string) {
	ar.unwrap_token = unwrap_token
}

// GetToken - returns a token for configured `role_id`
func (ar *AppRole) GetToken(c *hvault.Client) (token string, err error) {

	// lock reading the latest token
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	if nil != ar.auth {
		if len(ar.auth.ClientToken) != 0 && time.Now().UTC().Before(ar.expires) {
			return ar.auth.ClientToken, nil // returns valid saved token
		} else {
			err = ar.renew(c) // try to renew the existing token
			if nil == err {
				return ar.auth.ClientToken, err // if no error is detected, the renew was successful, otherwise we fallback to creating a new token
			}
		}
	}

	// prefer unwrap over given secret id
	if len(ar.unwrap_token) != 0 {
		err = ar.unwrap(c)
		if nil != err {
			return "", fmt.Errorf("gettoken: %w", err)
		}
		ar.unwrap_token = "" // unwrap tokens are 1 time use only so we don't keep them in memory anymore after using it
	}

	if len(ar.secret_id) == 0 {
		return "", fmt.Errorf("gettoken: missing 'secret_id' to get a valid token from Vault")
	}

	err = ar.new(c) // create new token
	if nil != err {
		return "", fmt.Errorf("gettoken: %w", err)
	}

	return ar.auth.ClientToken, err
}

// unwrap - unwraps the secret id
func (ar *AppRole) unwrap(c *hvault.Client) (err error) {

	c.SetToken(ar.unwrap_token)
	secret, err := c.Logical().Write("sys/wrapping/unwrap", nil)
	if nil != err {
		return fmt.Errorf("unwrap: %w", err)
	}

	ar.auth = new(hvault.SecretAuth)
	ttl, err := secret.Data["secret_id_ttl"].(json.Number).Int64()
	if nil != err {
		return fmt.Errorf("unwrap: %w", err)
	}

	ar.secret_id = secret.Data["secret_id"].(string)
	ar.auth.LeaseDuration = int(ttl)
	ar.setexpiry()

	return
}

// new - creates a new authentication secret
func (ar *AppRole) new(c *hvault.Client) (err error) {

	if len(ar.role_id) == 0 && len(ar.secret_id) == 0 {
		return fmt.Errorf("new: missing 'role_id' and 'secret_id' to get new token")
	}

	d := NewData()

	d.SetString("role_id", ar.role_id)
	d.SetString("secret_id", ar.secret_id)

	secret, err := c.Logical().Write(ar.path+"/login", d)
	if nil != err {
		return fmt.Errorf("new: %w", err)
	}

	ar.auth = secret.Auth
	ar.setexpiry()

	// we do not keep track of number of uses and such as Vault does a fantastic job of it, if it has expired Vault will let us know and we can return the error
	// we keep expiry of the token to be able to return it in an instant

	return
}

// renew - renews an existing token obtained from login
func (ar *AppRole) renew(c *hvault.Client) (err error) {

	if len(ar.auth.ClientToken) == 0 {
		return fmt.Errorf("renew: missing 'token' for renewal")
	}

	c.SetToken(ar.auth.ClientToken)
	secret, err := c.Logical().Write("auth/token/renew-self", nil)
	if nil != err {
		return fmt.Errorf("renew: %w", err)
	}

	ar.auth = secret.Auth
	ar.setexpiry()

	return
}

// setexpiry - sets an expiry datetime
func (ar *AppRole) setexpiry() {
	if ar.auth.LeaseDuration > 20 {
		ar.auth.LeaseDuration -= 10 // we set our maximum to be 10 seconds less than expiry
	}
	ar.expires = time.Now().Add(time.Duration(ar.auth.LeaseDuration) * time.Second).UTC()
}
