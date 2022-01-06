package vault

import hvault "github.com/hashicorp/vault/api"

// Auth - interface for different types of authentication supported by this library, standard is `token` and `approle`
//type Auth = hvault.AuthMethod

// Auth - interface for different types of authentication supported by this library, standard is `token` and `approle`
type Auth interface {
	GetToken(*hvault.Client) (string, error)
}

// Client - Vault Client instance and its related information
type Client struct {
	store    string
	attempts int
	retry    int
	client   *hvault.Client
	auth     Auth
}

// Data - vault data format
type Data map[string]interface{}

// KeyError - custom error for indicating a given key is not found
type KeyError struct {
	key string
}

// FieldError - custom error for fields under a key not found
type FieldError struct {
	field string
}

// ListError - custom error for listing paths under a key
type ListError struct {
	rootPath, path string
}
