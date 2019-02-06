package fincrypt

import "testing"

func Test_PVV(t *testing.T) {
	operation := PVVOperation{}
	operation.PAN = "5486960000008273"
	operation.PIN = "1234"
	operation.PVKI = "1"
	operation.PVK = "57E032204026015B04DCABE398B585A2"

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "5498"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
