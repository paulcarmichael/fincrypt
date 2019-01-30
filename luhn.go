package cryptop

import (
	"errors"
	"strconv"
)

// LuhnOperation struct to be populated by the caller
type LuhnOperation struct {
	Mode  int
	Input string
}

// Calculate performs an operation as described in the LuhnOperation variable, which should be populated by the caller
func (op LuhnOperation) Calculate() (string, error) {

	// validate the input
	if len(op.Input) == 0 {
		return "", errors.New("Input has zero length")
	}

	if NumericOnly(op.Input) == false {
		return "", errors.New("Input must be numeric digits only")
	}

	// if we are validating, we generate a luhn on the input without the last digit
	var data string

	if op.Mode == ModeValidate {
		data = op.Input[:len(op.Input)-1]
	} else {
		data = op.Input
	}

	// generate the luhn check digit
	sum := 0
	double := true

	for i := len(data) - 1; i >= 0; i-- {
		digit, err := strconv.Atoi(data[i : i+1])

		if err != nil {
			return "", err
		}

		if double == true {
			digit *= 2

			if digit > 9 {
				digit = (digit % 10) + 1
			}
		}

		double = !double
		sum += digit
	}

	return strconv.Itoa(10 - (sum % 10)), nil
}
