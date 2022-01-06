package vault

import (
	"encoding/base64"
	"fmt"
	"strconv"
)

// NewData - creates new instance of vault data
func NewData() (d Data) {
	return make(Data)
}

// Exist - checks if a given field exists
func (d Data) Exist(field string) bool {
	_, ok := d[field]
	return ok
}

// GetString - returns string value from a given field
func (d Data) GetString(field string) (value string) {
	value, ok := d[field].(string)
	if ok {
		return value
	}
	return
}

// GetBool - returns bool value from a given field
func (d Data) GetBool(field string) (value bool) {
	v, ok := d[field].(string)
	if ok {
		value, _ = strconv.ParseBool(v)
	}

	return
}

// GetUint64 - returns uint64 value from a given field
func (d Data) GetUint64(field string) (value uint64) {
	v, ok := d[field].(string)
	if ok {
		value, _ = strconv.ParseUint(v, 10, 64)
	}

	return
}

// GetBytes - returns bytes value from a given field (decoded from base64 URLEncoding)
func (d Data) GetBytes(field string) (bytes []byte, err error) {
	value, ok := d[field].(string)
	if !ok {
		return nil, fmt.Errorf("getbytes: no such field " + field)
	}

	if len(value) == 0 {
		return nil, fmt.Errorf("getbytes:" + field + " is empty")
	}

	return base64.URLEncoding.DecodeString(value)
}

// SetString - sets a field and value in string format
func (d Data) SetString(field, value string) {
	d[field] = value
}

// SetBool - sets a field and value in boolean format
func (d Data) SetBool(field string, value bool) {
	d[field] = strconv.FormatBool(value)
}

// SetUint64 - sets a field and value in uint64 format
func (d Data) SetUint64(field string, value uint64) {
	d[field] = strconv.FormatUint(value, 10)
}

// SetBytes - sets a field and value in bytes encoded using base64 URLEncoding
func (d Data) SetBytes(field string, value []byte) {
	d[field] = base64.URLEncoding.EncodeToString(value)
}
