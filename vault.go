package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	hvault "github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
)

// New - creates new instance of vault using the given information, other key pieces of information are based on the `VAULT_*` environment variables
//func New(config *hvault.Config, auth Auth, store string, output io.Writer) (v *Client, err error) {
func New(auth Auth, store string, output io.Writer) (v *Client, err error) {

	jww.SetLogOutput(output)
	jww.SetStdoutThreshold(jww.LevelInfo)

	v = new(Client)

	v.store = store
	v.attempts = 12 // this can be hardcoded
	v.retry = 5     // this can be hardcoded

	err = v.ok()
	if nil != err {
		return nil, fmt.Errorf("new: %w", err)
	}

	// make sure `VAULT_ADDR` is set otherwise return an error
	if v := os.Getenv(hvault.EnvVaultAddress); v == "" {
		return nil, fmt.Errorf("new: missing environment variable " + hvault.EnvVaultAddress)
	}

	config := hvault.DefaultConfig() // create an instance of config to be used

	sealStatus := &hvault.SealStatusResponse{}
	sleep := time.Duration(time.Second * time.Duration(v.retry))

	for i := 1; i <= v.attempts; i++ {
		v.client, err = hvault.NewClient(config) // vault will attempt to read environment variables, so lets leave the task to it
		if nil != err {
			return nil, fmt.Errorf("new: %w", err)
		}

		sealStatus, err = v.client.Sys().SealStatus()
		if nil != err {
			return nil, fmt.Errorf("new: seal status (1): %w", err)
		}

		if nil != sealStatus {
			break
		}

		jww.INFO.Printf("sleeping %d seconds to check vault status, attempt %d of %d", v.retry, i, v.attempts)
		time.Sleep(sleep) // retry every X seconds
	}

	if nil == sealStatus {
		return nil, fmt.Errorf("new: unable to obtain seal status of Vault")
	}

	for sealStatus.Sealed {
		//log.Println("Vault is sealed, waiting for it to be unsealed")
		jww.INFO.Println("vault is sealed, waiting for it to be unsealed")

		sealStatus, err = v.client.Sys().SealStatus()
		if nil != err {
			return nil, fmt.Errorf("new: seal status (2): %w", err)
		}

		time.Sleep(time.Second * time.Duration(v.retry)) // retry every X seconds to see if the vault is unsealed
	}

	v.auth = auth

	/*
		secret, err := auth.Login(context.TODO(), v.client)
		if nil != err {
			return nil, fmt.Errorf("new: auth: %w", err)
		}
		v.auth = secret.Auth
	*/

	return
}

// IsSealed - checks if Vault is currently sealed
func (v *Client) IsSealed() (sealed bool, err error) {

	sealStatus, err := v.client.Sys().SealStatus()
	if nil != err {
		return true, fmt.Errorf("issealed: seal status: %w", err)
	}

	return sealStatus.Sealed, nil
}

// ok - checks if the necessary information are correct and configures default values for the rest
func (v *Client) ok() (err error) {

	if len(v.store) == 0 {
		return errors.New("missing vault path")
	}

	if v.attempts == 0 {
		v.attempts = 12 // maximum times to retry vault status checking, default value
	}

	if v.retry == 0 {
		v.retry = 5 // retry attempt in seconds, default value
	}

	return
}

// Write - writes the vault data to the given path, this will **COMPLETELY** replace all values in the path
func (v *Client) Write(path string, d Data) (data Data, err error) {

	sealed, err := v.IsSealed()
	if nil != err {
		return
	}

	if sealed {
		return nil, fmt.Errorf("write: vault is currently sealed")
	}

	// get a valid token and connect to Vault
	token, err := v.auth.GetToken(v.client)
	if nil != err {
		return nil, fmt.Errorf("write: %w", err)
	}

	v.client.SetToken(token)

	c := v.client.Logical()
	if nil == c {
		return nil, errors.New("write: error creating logical client for Vault")
	}

	secret, err := c.Write(v.store+"/"+path, d)
	if nil != err {
		return nil, fmt.Errorf("write: %w", err)
	}

	if nil != secret && nil != secret.Data {
		data = secret.Data
	}

	return data, nil
}

// WriteKey - writes the given string value to the specific key under the given path
func (v *Client) WriteKey(path, field, value string) (data Data, err error) {

	d, err := v.Read(path)
	if nil != err {
		return nil, fmt.Errorf("writekey: %w", err)
	}

	d.SetString(field, value)

	return v.Write(path, d)
}

// Read - reads all the fields under the given path
func (v *Client) Read(path string) (data Data, err error) {

	sealed, err := v.IsSealed()
	if nil != err {
		return
	}

	if sealed {
		return nil, fmt.Errorf("read: vault is currently sealed")
	}

	// get a valid token and connect to Vault
	token, err := v.auth.GetToken(v.client)
	if nil != err {
		return nil, fmt.Errorf("read: %w", err)
	}

	v.client.SetToken(token)

	c := v.client.Logical()
	if nil == c {
		return nil, errors.New("read: error creating logical client for Vault")
	}

	secret, err := c.Read(v.store + "/" + path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	if nil == secret {
		return nil, fmt.Errorf("read: %w", NewKeyError(path))
	}

	return secret.Data, nil
}

// ReadKey - reads the specific key under the given path and returns a string value
func (v *Client) ReadKey(path string, field string) (value string, err error) {

	d, err := v.Read(path)
	if nil != err {
		return "", fmt.Errorf("get: %w", err)
	}

	value = d.GetString(field)
	if len(value) == 0 {
		return "", fmt.Errorf("get: %w", NewFieldError(field))
	}

	return

}

// Delete - delete the given key
func (v *Client) Delete(path string) (data Data, err error) {

	sealed, err := v.IsSealed()
	if nil != err {
		return
	}

	if sealed {
		return nil, fmt.Errorf("delete: vault is currently sealed")
	}

	// get a valid token and connect to Vault
	token, err := v.auth.GetToken(v.client)
	if nil != err {
		return nil, fmt.Errorf("delete: %w", err)
	}

	v.client.SetToken(token)

	c := v.client.Logical()
	if nil == c {
		return nil, errors.New("delete: error creating logical client for Vault")
	}

	secret, err := c.Delete(v.store + "/" + path)
	if nil != err {
		return nil, fmt.Errorf("delete: %w", err) // reformat the error message for consistency
	}

	if nil == secret {
		return // return immediately if there is no secret returned, we don't care if the path actually existed or not
	}

	return secret.Data, nil
}

// List - list keys under a given path
func (v *Client) List(path string) (keys []string, err error) {

	sealed, err := v.IsSealed()
	if nil != err {
		return
	}

	if sealed {
		return nil, fmt.Errorf("delete: vault is currently sealed")
	}

	// get a valid token and connect to Vault
	token, err := v.auth.GetToken(v.client)
	if nil != err {
		return nil, fmt.Errorf("delete: %w", err)
	}

	v.client.SetToken(token)

	c := v.client.Logical()
	if nil == c {
		return nil, errors.New("list: error creating logical client for Vault")
	}

	secret, err := c.List(v.store + "/" + path)
	if nil != err {
		return
	}

	if nil == secret {
		return nil, NewListError(v.store, path)
	}

	for _, k := range secret.Data["keys"].([]interface{}) {
		keys = append(keys, k.(string))
	}

	return
}
