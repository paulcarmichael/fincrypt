package fincrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"math/big"
	"strconv"
)

// RSAOperation to be instantiated and populated by the caller
type RSAOperation struct {
	Input           string
	PublicExponent  string
	PrivateExponent string
	Modulus         string
	Label           string
	HashMode        HashMode
	Direction       Direction
}

// Calculate the result of an RSA operation, as described by an instance of RSAOperation
func (op RSAOperation) Calculate() (string, error) {
	// validate the inputs
	var err error
	op.Input, err = Pack(op.Input, InputNameInput)

	if err != nil {
		return "", err
	}

	_, err = Pack(op.PublicExponent, InputNamePublicExponent)

	if err != nil {
		return "", err
	}

	_, err = Pack(op.PrivateExponent, InputNameModulus)

	if err != nil {
		return "", err
	}

	_, err = Pack(op.Modulus, InputNameModulus)

	if err != nil {
		return "", err
	}

	// prepare the public key
	iPublicExponent, err := strconv.ParseInt(op.PublicExponent, 16, 32)

	if err != nil {
		return "", err
	}

	iModulus := new(big.Int)
	iModulus.SetString(op.Modulus, 16)

	var publicKey rsa.PublicKey
	publicKey.E = int(iPublicExponent)
	publicKey.N = iModulus

	// prepare the hash mode
	var hash hash.Hash

	if op.HashMode == HashModeSHA1 {
		hash = sha1.New()
	} else if op.HashMode == HashModeSHA224 {
		hash = sha256.New224()
	} else if op.HashMode == HashModeSHA256 {
		hash = sha256.New()
	} else if op.HashMode == HashModeSHA384 {
		hash = sha512.New384()
	} else if op.HashMode == HashModeSHA512 {
		hash = sha512.New()
	} else {
		return "", errors.New("Unknown hash mode")
	}

	// prepare the label
	var label []byte

	if len(op.Label) > 0 {
		label = []byte(op.Label)
	} else {
		label = nil
	}

	// perform the operation
	var r []byte

	if op.Direction == DirectionEncrypt {
		r, err = rsa.EncryptOAEP(hash, rand.Reader, &publicKey, []byte(op.Input), label)
	} else {
		// prepare the private key
		iPrivateExponent := new(big.Int)
		iPrivateExponent.SetString(op.PrivateExponent, 16)

		var privateKey rsa.PrivateKey
		privateKey.D = iPrivateExponent
		privateKey.PublicKey = publicKey

		r, err = rsa.DecryptOAEP(hash, nil, &privateKey, []byte(op.Input), label)
	}

	if err != nil {
		return "", err
	}

	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	return result, err
}
