package fincrypt

import "testing"

func Test_HMAC_SHA1(t *testing.T) {
	operation := HMACOperation{}
	operation.Key = "6B6579"                                                                                  // key
	operation.Data = "54686520717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F67" // The quick brown fox jumps over the lazy dog
	operation.HashMode = HashModeSHA1

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "DE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_HMAC_SHA256(t *testing.T) {
	operation := HMACOperation{}
	operation.Key = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
	operation.Data = "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
	operation.HashMode = HashModeSHA256

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "372EFCF9B40B35C2115B1346903D2EF42FCED46F0846E7257BB156D3D7B30D3F"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_HMAC_SHA384(t *testing.T) {
	operation := HMACOperation{}
	operation.Key = "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665" // JefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefe
	operation.Data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f"                                        // what do ya want for nothing?
	operation.HashMode = HashModeSHA384

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "2C7353974F1842FD66D53C452CA42122B28C0B594CFB184DA86A368E9B8E16F5349524CA4E82400CBDE0686D403371C9"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_HMAC_SHA512(t *testing.T) {
	operation := HMACOperation{}
	operation.Key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
	operation.Data = "4869205468657265"
	operation.HashMode = HashModeSHA512

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "637EDC6E01DCE7E6742A99451AAE82DF23DA3E92439E590E43E761B33E910FB8AC2878EBD5803F6F0B61DBCE5E251FF8789A4722C1BE65AEA45FD464E89F8F5B"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_HMAC_SHA512_LargeKey(t *testing.T) {
	operation := HMACOperation{}
	operation.Key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	operation.Data = "54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374" // Test Using Larger Than Block-Size Key - Hash Key First                                                                                                              // Hi There
	operation.HashMode = HashModeSHA512

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_HMAC_MD5(t *testing.T) {
	operation := HMACOperation{}
	operation.Key = "6B6579"                                                                                  // key
	operation.Data = "54686520717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F67" // The quick brown fox jumps over the lazy dog
	operation.HashMode = HashModeMD5

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "80070713463E7749B90C2DC24911E275"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
