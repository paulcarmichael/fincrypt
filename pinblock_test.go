package fincrypt

import (
	"encoding/json"
	"testing"
)

func Test_PINBlock_ISO0(t *testing.T) {
	operation := PINBlockOperation{}
	operation.PAN = "43219876543210987"
	operation.PIN = "1234"
	operation.PPK = "11111111111111111111111111111111"
	operation.PBF = PINBlockFormatISO0

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "{\"ClearPINBlock\":\"0412AC89ABCDEF67\",\"EncryptedPINBlock\":\"A8DA9831DB136FF0\"}"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_PINBlock_ISO1(t *testing.T) {
	operation := PINBlockOperation{}
	operation.PAN = "43219876543210987"
	operation.PIN = "1234"
	operation.PPK = "11111111111111111111111111111111"
	operation.PBF = PINBlockFormatISO1

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	var r PINBlockResult
	err = json.Unmarshal([]byte(result), &r)

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "141234"

	if r.ClearPINBlock[:6] != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_PINBlock_ISO2(t *testing.T) {
	operation := PINBlockOperation{}
	operation.PAN = "43219876543210987"
	operation.PIN = "1234"
	operation.PPK = "11111111111111111111111111111111"
	operation.PBF = PINBlockFormatISO2

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "{\"ClearPINBlock\":\"241234FFFFFFFFFF\",\"EncryptedPINBlock\":\"B86D4114C406E0D8\"}"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_PINBlock_ISO3(t *testing.T) {
	operation := PINBlockOperation{}
	operation.PAN = "43219876543210987"
	operation.PIN = "1234"
	operation.PPK = "11111111111111111111111111111111"
	operation.PBF = PINBlockFormatISO3

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	var r PINBlockResult
	err = json.Unmarshal([]byte(result), &r)

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "3412AC"

	if r.ClearPINBlock[:6] != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
