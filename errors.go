package vault

import (
	"fmt"
)

// NewKeyError - creates a new instance of key error
func NewKeyError(key string) (k *KeyError) {
	k = new(KeyError)
	k.key = key
	return
}

// Error - returns the error string
func (k *KeyError) Error() string {
	return ErrKeyNotFound(k.key).Error()
}

func (k *KeyError) Is(target error) bool {
	return k.Error() == target.Error()
}

// ErrKeyNotFound - specific error message indicating key is not found
func ErrKeyNotFound(key string) error {
	return fmt.Errorf("vault: key %s does not exist", key)
}

// NewFieldError - creates a new instance of field error
func NewFieldError(field string) (f *FieldError) {
	f = new(FieldError)
	f.field = field
	return
}

// Error - returns the error string
func (f *FieldError) Error() string {
	return ErrFieldNotFound(f.field).Error()
}

func (f *FieldError) Is(target error) bool {
	return f.Error() == target.Error()
}

// ErrFieldNotFound - specific error message indicating field is not found
func ErrFieldNotFound(key string) error {
	return fmt.Errorf("vault: field %s does not exist", key)
}

// NewListError - creates a new instance of list error
func NewListError(rootPath, path string) (l *ListError) {
	l = new(ListError)
	l.rootPath = rootPath
	l.path = path
	return
}

// Error - returns the error string
func (l *ListError) Error() string {
	return ErrListPathNotFound(l.path).Error()
}

func (l *ListError) Is(target error) bool {
	return l.Error() == target.Error()
}

// ErrListPathNotFound - specific error message indicating list path is not found
func ErrListPathNotFound(path string) error {
	return fmt.Errorf("list: no keys found for given path %q", path)
}
