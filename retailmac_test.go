package fincrypt

import "testing"

func Test_RetailMAC(t *testing.T) {
	operation := RetailMACOperation{}
	operation.Key = "D0C8B843CFEDD831E7A63B41F7FD0422"
	operation.Data = "00000000150000000000000008400000040000084014111900019A5199180000070FA501250000000000000000000000000F200000000000000000000000000000"
	operation.Padding = "M2"

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "F80E46ED7AD92FF1"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
