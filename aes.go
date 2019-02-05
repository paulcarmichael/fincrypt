package fincrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AESOperation struct to be populated by the caller
type AESOperation struct {
	Direction Direction
	Mode      CipherMode
	Key       string
	Data      string
	IV        string
}

// Calculate performs a crypto operation as described in the AESOperation variable, which should be populated by the caller
func (op AESOperation) Calculate() (string, error) {
	// pack the key, data, and IV
	var err error
	op.Key, err = Pack(op.Key, InputNameKey)

	if err != nil {
		return "", err
	}

	op.Data, err = Pack(op.Data, InputNameData)

	if err != nil {
		return "", err
	}

	op.IV, err = Pack(op.IV, InputNameIV)

	if err != nil {
		return "", err
	}

	// validate the key length
	keyLength := len(op.Key)

	if keyLength == 16 || // AES-128
		keyLength == 24 || // AES-192
		keyLength == 32 { // AES-256
		//happy
	} else {
		return "", errors.New("Key must be 16/24/32 bytes")
	}

	// prepare the key
	block, err := aes.NewCipher([]byte(op.Key))

	if err != nil {
		return "", err
	}

	// validate the data - it must be a multiple of the block size
	blockSize := block.BlockSize()

	if len(op.Data)%blockSize != 0 {
		return "", errors.New("Data length must be a multiple of the block size (16 bytes)")
	}

	// prepare a buffer for the result
	r := make([]byte, len(op.Data))

	// the caller specifies the direction and mode
	if op.Mode == CipherModeCBC {
		// validate the iv length
		if len(op.IV) != 16 {
			return "", errors.New("IV must be 16 bytes")
		}

		var blockMode cipher.BlockMode

		if op.Direction == DirectionEncrypt {
			blockMode = cipher.NewCBCEncrypter(block, []byte(op.IV))
		} else {
			blockMode = cipher.NewCBCDecrypter(block, []byte(op.IV))
		}

		blockMode.CryptBlocks(r, []byte(op.Data))
	} else if op.Mode == CipherModeECB { // cipher provides no ECB crypters, so do it manually by the block
		data := []byte(op.Data)

		if op.Direction == DirectionEncrypt {
			for pos := 0; pos < len(op.Data); pos += blockSize {
				block.Encrypt(r[pos:], data[pos:])
			}
		} else {
			for pos := 0; pos < len(op.Data); pos += blockSize {
				block.Decrypt(r[pos:], data[pos:])
			}
		}
	}

	// expand the result
	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	return result, nil
}
