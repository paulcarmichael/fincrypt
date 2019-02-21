package fincrypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
)

// SHAMode specifies the types of SHA
type SHAMode string

// SHAMode types of SHA
const (
	SHAModeSHA1   SHAMode = "SHA-1"
	SHAModeSHA224         = "SHA-224"
	SHAModeSHA256         = "SHA-256"
	SHAModeSHA384         = "SHA-384"
	SHAModeSHA512         = "SHA-512"
)

// SHAOperation to be populated by the caller
type SHAOperation struct {
	Input string
	Mode  SHAMode
}

// Calculate generates the hash of SHAOperation input string
func (op SHAOperation) Calculate() (string, error) {
	if len(op.Input) == 0 {
		return "", errors.New("Input has zero length")
	}

	var h hash.Hash

	if op.Mode == SHAModeSHA1 {
		h = sha1.New()
	} else if op.Mode == SHAModeSHA224 {
		h = sha256.New224()
	} else if op.Mode == SHAModeSHA256 {
		h = sha256.New()
	} else if op.Mode == SHAModeSHA384 {
		h = sha512.New384()
	} else if op.Mode == SHAModeSHA512 {
		h = sha512.New()
	} else {
		return "", errors.New("Unknown SHA mode")
	}

	h.Write([]byte(op.Input))

	return hex.EncodeToString(h.Sum(nil)), nil
}
