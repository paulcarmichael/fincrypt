package fincrypt

import (
	"crypto/des"
	"errors"
	"strconv"
	"strings"
)

// PINOffsetOperation struct to be populated be the caller
type PINOffsetOperation struct {
	PAN string
	PIN string
	PVK string
	DT  string
}

// Calculate generates a natural PIN and PIN offset from data populated in a PINOffsetOperation variable
func (op PINOffsetOperation) Calculate() (string, error) {

	// validate the lengths of the input elements
	if len(op.PAN) == 0 {
		return "", errors.New("PAN field is empty")
	}

	if len(op.PIN) == 0 {
		return "", errors.New("PIN field is empty")
	}

	if len(op.PIN) > 16 {
		return "", errors.New("PIN field can be a maximum of 16 digits long")
	}

	if len(op.PVK) != 32 &&
		len(op.PVK) != 48 {
		return "", errors.New("PVK field must be 32 or 48 digits long")
	}

	if len(op.DT) != 16 {
		return "", errors.New("Decimalisation Table must be 16 digits long")
	}

	// check the decimalisation table is numeric digits only
	if NumericOnly(op.DT) == false {
		return "", errors.New("Decimalidation Table must be numeric digits only")
	}

	// pack the PVK
	var err error

	op.PVK, err = Pack(op.PVK, InputNamePVK)

	if err != nil {
		return "", err
	}

	// build the validation data
	var b strings.Builder

	if len(op.PAN) < 16 {
		b.WriteString(strings.Repeat("0", 16-len(op.PAN)))
		b.WriteString(op.PAN)
	} else {
		b.WriteString(op.PAN[:16])
	}

	// pack the validation data
	vd, err := Pack(b.String(), InputNameInput)

	if err != nil {
		return "", err
	}

	// prepare the PVK
	if len(op.PVK) == 16 {
		op.PVK += op.PVK[:8]
	}

	k, err := des.NewTripleDESCipher([]byte(op.PVK))

	if err != nil {
		return "", err
	}

	// prepare a buffer for the result
	r := make([]byte, k.BlockSize())

	// encrypt the validation data with the PVK
	k.Encrypt(r, []byte(vd))

	// decimalise the result
	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	// pass the result through the decimalisation table
	for i := 0; i <= len(op.DT)-1; i++ {
		result = strings.Replace(result, // source string
			strings.ToUpper(strconv.FormatInt(int64(i), 16)), // convert i to a string and then uppercase it, e.g 12 -> c -> C
			string(op.DT[i]), // replacement digit from the decimalisation table
			-1)               // replace all matches
	}

	// calculate the offset
	var offset string
	var pinDigit int64
	var naturalDigit int64
	var offsetDigit int64

	for i := 0; i <= len(op.PIN)-1; i++ {

		pinDigit, err = strconv.ParseInt(string(op.PIN[i]), 10, 16)

		if err != nil {
			return "", err
		}

		naturalDigit, err = strconv.ParseInt(string(result[i]), 10, 16)

		if err != nil {
			return "", err
		}

		offsetDigit = pinDigit - naturalDigit

		if offsetDigit < 0 {
			offsetDigit = 10 - -offsetDigit
		}

		offset += strconv.FormatInt(offsetDigit, 10)
	}

	return offset, nil
}
