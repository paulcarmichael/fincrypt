package fincrypt

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"hash"

	"golang.org/x/crypto/md4"
)

// MDMode specifies the type of MD hash
type MDMode string

// MDMode types of MD hash
const (
	MDModeMD4 MDMode = "MD4"
	MDModeMD5        = "MD5"
)

// MDOperation to be populated by the caller
type MDOperation struct {
	Input string
	Mode  MDMode
}

// Calculate generates the hash of MDOperation input string
func (op MDOperation) Calculate() (string, error) {
	if len(op.Input) == 0 {
		return "", errors.New("Input has zero length")
	}

	var h hash.Hash

	if op.Mode == MDModeMD4 {
		h = md4.New()
	} else if op.Mode == MDModeMD5 {
		h = md5.New()
	} else {
		return "", errors.New("Unknown MD mode")
	}

	h.Write([]byte(op.Input))

	return hex.EncodeToString(h.Sum(nil)), nil
}
