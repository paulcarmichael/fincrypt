package fincrypt

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"

	"golang.org/x/crypto/md4"
)

// HashOperation to be populated by the caller
type HashOperation struct {
	Input    string
	HashMode HashMode
}

// Calculate generates the hash of SHAOperation input string
func (op HashOperation) Calculate() (string, error) {
	if len(op.Input) == 0 {
		return "", errors.New("Input has zero length")
	}

	var h hash.Hash

	if op.HashMode == HashModeSHA1 {
		h = sha1.New()
	} else if op.HashMode == HashModeSHA224 {
		h = sha256.New224()
	} else if op.HashMode == HashModeSHA256 {
		h = sha256.New()
	} else if op.HashMode == HashModeSHA384 {
		h = sha512.New384()
	} else if op.HashMode == HashModeSHA512 {
		h = sha512.New()
	} else if op.HashMode == HashModeMD4 {
		h = md4.New()
	} else if op.HashMode == HashModeMD5 {
		h = md5.New()
	} else {
		return "", errors.New("Unknown hash mode")
	}

	h.Write([]byte(op.Input))

	return hex.EncodeToString(h.Sum(nil)), nil
}
