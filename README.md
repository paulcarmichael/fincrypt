# fincrypt
A go library which provides general purpose cryptography alongside solutions for payment industry specific requirements.

fincrypt offers simple drop in support, with robust error reporting, which is backed unit tests.

Operation support includes,

* Authentication Codes (MACs)
  * HMAC (SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/MD4/MD5)
  * Retail MAC (ISO-9797-1)
  
* Cardholder Validation
  * CVVs (CVV/CVV2/iCVV)
  * PIN Blocks (ISO0/ISO1/ISO2/ISO3)
  * PIN Offset
  * PVV
  
* Ciphers
  * AES (ECB/CBC)
  * TDES (ECB/CBC)
  * RSA (OAEP)
  
* EMV 4.3
  * Tag Search
  * TLV Parsing
  
* Hashes
  * MD4/5
  * SHA-1/SHA-224/SHA-256/SHA-384/SHA-512
  
* Utilities
  * Base64
  * Luhn Check Digit
  * XOR
