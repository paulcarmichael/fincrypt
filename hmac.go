package fincrypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

	"golang.org/x/crypto/md4"
)

// HMACOperation calculates a HMAC
type HMACOperation struct {
	Key      string
	Data     string
	HashMode HashMode
}

// Calculate uses the HMACOperation variables to calculate a HMAC
func (op HMACOperation) Calculate() (string, error) {
	// validate the inputs
	var err error

	op.Key, err = Pack(op.Key, InputNameKey)

	if err != nil {
		return "", err
	}

	op.Data, err = Pack(op.Data, InputNameData)

	if err != nil {
		return "", err
	}

	// setup the hash function
	var hf func() hash.Hash

	if op.HashMode == HashModeSHA1 {
		hf = sha1.New
	} else if op.HashMode == HashModeSHA224 {
		hf = sha256.New224
	} else if op.HashMode == HashModeSHA256 {
		hf = sha256.New
	} else if op.HashMode == HashModeSHA384 {
		hf = sha512.New384
	} else if op.HashMode == HashModeSHA512 {
		hf = sha512.New
	} else if op.HashMode == HashModeMD4 {
		hf = md4.New
	} else if op.HashMode == HashModeMD5 {
		hf = md5.New
	} else {
		return "", errors.New("Unknown hash mode")
	}

	// calculate the mac
	hm := hmac.New(hf, []byte(op.Key))
	hm.Write([]byte(op.Data))

	r, err := Expand(hm.Sum(nil))

	if err != nil {
		return "", err
	}

	return r, nil
}
