# Golang helper library to interact with Hashicorp Vault

Helper library to manage connection to Hashicorp Vault, allowing it to be used as a generic datastore using key/value store. Vault was not meant to be used as such however it fits the bill in some cases, especially with regards to storing identities and credentials of users for applications. Vault is tried and tested with regards to its security that re-implementing its features in our own application is a moot point. 

**NOTE**: This library relies on `VAULT_*` environment variables to configure Vault. Some of the key Vault environment variables that can be configured are

- `VAULT_ADDR` 			    = address of the Vault instance (**REQUIRED**)
- `VAULT_CACERT`			= path to pem encoded CA file to verify Vault server by client (this takes precedence over VAULT_CACERT)
- `VAULT_CAPATH`			= path to directory storing pem encoded CA files to verify Vault server by client
- `VAULT_CLIENT_CERT`		= path to pem encoded client certificate for communication with Vault server
- `VAULT_CLIENT_KEY`		= path to pem encoded client key for communication with Vault server
- `VAULT_CLIENT_TIMEOUT`	= timeout by client
- `VAULT_SKIP_VERIFY`		= skip verifying Vault server certificate
- `VAULT_TLS_SERVER_NAME`	= name to use as Server Name Indication (SNI) when connecting over TLS
- `VAULT_HTTP_PROXY`		= proxy to be used by client when connecting to Vault server

## Usage example

Some examples of using this library is given below. It is recommended to use `AppRole` over `Token` when possible however do take note on the generation of `secret_id` and `token`. These values are not meant to be long lived therefore it could expire for a long lived application. It would mean having to create new `secret_id` and restarting the application periodically OR using `vault agent` to write a `token` to a file to be read by the library. Please choose the best way to distribute and store these information for your own applications.

Instructions are given at the end of this document on how to generate really long lived `secret_id`.

## Authentication

Access to Vault is tightly controlled, which requires a valid token. These tokens will be renewed as needed, should the tokens expire or its maximum use is reached.

Use either `AppRole` or `Token`, depending on preference or need

### Using AppRole

`role_name` **MUST** match the role given during creation of this `AppRole`.

```go
auth := vault.NewAppRole(vault.AppRolePath, role_name, role_id)
auth.SetSecretID(secret_id)
```

### Using Token

```go
auth := vault.NewToken(token)
auth.SetToken(token)
```

## Creating new client

`store` represents the Vault Key/Value store where the data is stored. This helps the library narrow down the scope without being overly verbose in reading, writing or deleting.

```go
client, err := vault.New(auth, store, os.Stdout)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
```

### Using TLS with Vault

Ideally, Vault is secured using TLS certificates for information exchange. Setting up TLS is done using the following environment `VAULT_*` variables.

To setup spefific CA for verifying Vault TLS certificate, set either of the following environment variables
- `VAULT_CACERT`			= path to pem encoded CA file to verify Vault server by client (this takes precedence over VAULT_CACERT) 
- `VAULT_CAPATH`			= path to directory storing pem encoded CA files to verify Vault server by client

For optional TLS authentication against Vault server, the client cert can be specified 
- `VAULT_CLIENT_CERT`		= path to pem encoded client certificate for communication with Vault server
- `VAULT_CLIENT_KEY`		= path to pem encoded client key for communication with Vault server

If the client wishes to skip verifying the Vault server cert, set the following environment variable. This should not be done in most cases. If a custom CA is used, specify the CA file as above.
- `VAULT_SKIP_VERIFY`		= skip verifying Vault server certificate

Specify how long the client should wait
- `VAULT_CLIENT_TIMEOUT`	= timeout by client

Specify an SNI if connecting to a server serving multiple certs under a single IP address
- `VAULT_TLS_SERVER_NAME`	= name to use as Server Name Indication (SNI) when connecting over TLS

## Adding data to Vault key/value store

```go
// create new data to write
data := vault.NewData()
data.SetString("hello", "world!")
data.SetBool("enabled", true)
data.SetUint64("duration", 1234)

blk = make([]byte, 32)
_, err = rand.Read(blk)
data.SetBytes("bytes", blk)

_, err = client.Write("test", data)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
```

## Reading data from Vault key/value store

```go
result, err := client.Read("test")
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Println(result.GetString("test"))
fmt.Println(result.GetBool("enabled"))
fmt.Println(result.GetUint64("duration"))

blk,err = result.GetUint64("bytes")
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Println(blk)
```

## Deleting data from Vault key/value store

```go
_, err = client.Delete("test")
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
```

## Create approle `role_id` and `secret_id`

This library prefers the usage of the `AppRole` authentication method to interact with items in Vault. Below is a simple guide to setup `AppRole` to acquire the `role_id` and `secret_id`.

For a full guide, refer to [https://learn.hashicorp.com/tutorials/vault/approle](https://learn.hashicorp.com/tutorials/vault/approle).

1. Export the necessary variables to connect to the required Vault instance.
2. Make sure to have the root (or similar) token to configure the authentication methods.
3. Enable the `AppRole` auth method
```bash
vault auth enable approle
```
4. Create a new policy and attach the role to that policy, in this example the policy name is `policy-keystore`
```bash
vault policy write policy-keystore -<<EOF
path "keystore/*" {  capabilities = ["create", "read", "update", "delete", "list"]}
path "keystore/config" {  capabilities = ["read", "list"]}
EOF
```
5. Create a named role for the application (`app-keystore` in this example), modifying the values as needed. Consider limiting `secret_id_num_uses` if needed, however that means another way to provide the new `secret_id` must be managed
```bash
vault write auth/approle/role/app-keystore \
    token_policies="policy-keystore" \
    secret_id_ttl=8760h \
    token_ttl=30m \
    token_max_ttl=2h \
    token_num_uses=5 \
    secret_id_num_uses=0
```
6.Fetch the `role_id` of the newly created `AppRole`, replacing `app-keystore` with the name given for the role in step (5). `role_id` is similar to a username so the value will be the same everytime this is called
```bash
vault read auth/approle/role/app-keystore/role-id
```
7. Get `secret_id` for this approle, this information must be kept private and secure. Replace `app-keystore` with the name given for the role in step (5)
```bash
vault write -f auth/approle/role/app-keystore/secret-id
```
8. Supply the `role_id` and `secret_id` to the library to faciliate interaction between this library and the Vault instance.
9. To test if the `role_id` and `secret_id` works, try to login from the command line. If it returns a bunch of information such as token, lifetime, etc then it is working as intended
```bash
vault write auth/approle/login role_id="role_id" secret_id="secret_id"
```
10. Alternatively, instead of providing the `secret_id` directly, it can be obtained using the response wrapping feature of Vault. To get the `wrapping_token`, run the following instead of step (7), replacing `app-keystore` with the name given for the role in step (5) 
```bash
vault write -wrap-ttl=1h -f auth/approle/role/app-keystore/secret-id
```

### Creating extremely long lived secret ids

**USE THIS CAREFULLY**. Know what you are doing and why you need this before proceeding.

While Vault expects a limited lifetime for `secret_id` and `token`, sometimes it could be necessary to create extremely long lived `secret_id` and `token` especially if using Vault as a datastore.

The TTL for secret ids cannot be more than what is configured for Vault. To override this, we need to instruct Vault to change the TTL for a specific authentication method. Below are instructions for creating extremely long lived secret ids.

1. Tune the endpoint for `AppRole`, replace `approle` with the path configured for your `AppRole` Vault instance. The maximum value Vault supports is `999999999` seconds.
```bash
vault auth tune -default-lease-ttl=8760h -max-lease-ttl=17520h approle/
```

2. Now when you create secret ids, it will use the TTL specified here or in step (5) above, whichever is lower.
