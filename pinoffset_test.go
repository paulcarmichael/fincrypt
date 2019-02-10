package fincrypt

import "testing"

func Test_PINOffset(t *testing.T) {
	operation := PINOffsetOperation{}
	operation.PAN = "7824464731112340"
	operation.PIN = "1234"
	operation.PVK = "11111111111111111111111111111111"
	operation.DT = "0123456789012345"

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "{\"NaturalPIN\":\"2582\",\"PINOffset\":\"9752\"}"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
