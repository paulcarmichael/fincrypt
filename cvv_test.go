package cryptop

import "testing"

func Test_CVV(t *testing.T) {
	operation := CVVOperation{}
	operation.PAN = "5486960000008273"
	operation.Expiry = "1812"
	operation.ServiceCode = "201"
	operation.CVK = "85321049CE2CE9CD32D6F87FD5CD808A"

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "{\"CVV\":\"207\",\"CVV2\":\"518\",\"ICVV\":\"571\"}"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
