package fincrypt

import (
	"crypto/des"
	"encoding/json"
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// PINBlockFormat specifies a PIN block format
type PINBlockFormat string

// PINBlockFormat enum lists supports PIN block formats
const (
	PINBlockFormatISO0 PINBlockFormat = "ISO0"
	PINBlockFormatISO1                = "ISO1"
	PINBlockFormatISO2                = "ISO2"
	PINBlockFormatISO3                = "ISO3"
)

// PINBlockOperation used to calculate clear and encrypted PIN blocks
type PINBlockOperation struct {
	PAN string
	PIN string
	PPK string
	PBF PINBlockFormat
}

// PINBlockResult contains the clear and encrypted PIN blocks
type PINBlockResult struct {
	ClearPINBlock     string
	EncryptedPINBlock string
}

// Calculate returns a PINBlockResult containing the clear and encrypted PIN blocks
func (op PINBlockOperation) Calculate() (string, error) {
	// validate inputs
	panLength := len(op.PAN)

	if op.PBF == PINBlockFormatISO0 || op.PBF == PINBlockFormatISO3 {
		if panLength < 12 {
			return "", errors.New(string(op.PBF) + " PAN must be at least 13 digits")
		}

		if NumericOnly(op.PAN) == false {
			return "", errors.New(string(op.PBF) + " PAN must be numeric digits only")
		}
	} else if op.PBF == PINBlockFormatISO1 || op.PBF == PINBlockFormatISO2 {
		op.PAN = ""
	} else {
		return "", errors.New("Unknown PIN block format")
	}

	// validate PIN
	pinLength := len(op.PIN)

	if pinLength < 4 && pinLength > 12 {
		return "", errors.New("PIN must be between 4 and 12 digits long")
	}

	if NumericOnly(op.PIN) == false {
		return "", errors.New("PIN must be numeric digits only")
	}

	// validate and prepare PPK length
	if len(op.PPK) != 32 && len(op.PPK) != 48 {
		return "", errors.New("PPK must be 16 bytes (32 digits) or 24 bytes (48 digits) long")
	}

	var err error
	op.PPK, err = Pack(op.PPK, InputNamePPK)

	if err != nil {
		return "", err
	}

	if len(op.PPK) == 16 {
		op.PPK += op.PPK[:8]
	}

	k, err := des.NewTripleDESCipher([]byte(op.PPK))

	if err != nil {
		return "", err
	}

	// build the clear PIN block
	// first the PIN data
	var b strings.Builder
	var cPB []byte
	var PINData string

	if op.PBF == PINBlockFormatISO0 || op.PBF == PINBlockFormatISO2 {
		if op.PBF == PINBlockFormatISO0 {
			b.WriteString("0")
		} else {
			b.WriteString("2")
		}

		b.WriteString(strconv.FormatInt(int64(pinLength), 16))
		b.WriteString(op.PIN)
		b.WriteString(strings.Repeat("F", 14-pinLength))

		PINData = b.String()
	} else if op.PBF == PINBlockFormatISO1 || op.PBF == PINBlockFormatISO3 {
		if op.PBF == PINBlockFormatISO1 {
			b.WriteString("1")
		} else {
			b.WriteString("3")
		}

		b.WriteString(strconv.FormatInt(int64(pinLength), 16))
		b.WriteString(op.PIN)

		seed := rand.NewSource(time.Now().UnixNano())
		rand := rand.New(seed)

		var pad string

		if op.PBF == PINBlockFormatISO1 {
			for b.Len() < 16 {
				pad = strconv.FormatInt(rand.Int63n(15), 16)
				b.WriteString(pad)
			}
		} else {
			for b.Len() < 16 {
				pad = strconv.FormatInt(rand.Int63n(5)+10, 16)
				b.WriteString(pad)
			}
		}

		PINData = b.String()
	}

	PINData, err = Pack(PINData, InputNameInput)

	if err != nil {
		return "", err
	}

	// build the PAN data, if PAN data is not required then the PINData alone is the clear PIN block
	if op.PBF == PINBlockFormatISO0 || op.PBF == PINBlockFormatISO3 {
		b.Reset()
		b.WriteString("0000")
		b.WriteString(op.PAN[panLength-13 : panLength-1])

		PANData, err := Pack(b.String(), InputNameInput)

		if err != nil {
			return "", err
		}

		// xor to calculate the clear PIN block
		cPB = XOR([]byte(PINData), []byte(PANData))
	} else if op.PBF == PINBlockFormatISO1 || op.PBF == PINBlockFormatISO2 {
		cPB = []byte(PINData)
	}

	// prepare a buffer for the result
	r := make([]byte, k.BlockSize())

	// encrypt the clear PIN block with the PPK
	k.Encrypt(r, cPB)

	// return the calculate PIN blocks
	var result PINBlockResult

	result.ClearPINBlock, err = Expand(cPB)

	if err != nil {
		return "", err
	}

	result.EncryptedPINBlock, err = Expand(r)

	if err != nil {
		return "", err
	}

	resultBytes, err := json.Marshal(result)

	if err != nil {
		return "", errors.New("Failed to convert calculated PIN blocks to json")
	}

	return string(resultBytes), nil
}
