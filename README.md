
# golang-jwt for Yubikey

Another extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) that allows creating and verifying JWT tokens where the private key is embedded inside  [PIV-enabled Yubikey](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html).

for reference, see 

* [golang-jwt for Trusted Platform Module TPM](https://github.com/salrashid123/golang-jwt-tpm)
* [YubiKeyTokenSource](https://github.com/salrashid123/yubikey)

To Start, you need a special yubikey and a certificte enabled for signing installed.  It should be installed in slot `9c` as shown here.

You can generate the key on the Yubikey (preferable) or import it

![images/yubikey_cert.png](images/yubikey_cert.png)

Either way, it should look like htis:

```bash
$ yubico-piv-tool  -a status
	Version:	5.2.7
	Serial Number:	13981219
	CHUID:	3019d4e739da739ced39ce739d836858210842108421c84210c3eb3410580d44ea9aa3cb26993084513cb2a39d350832303330303130313e00fe00
	CCC:	No data available
	Slot 9c:	
		Algorithm:	RSA2048
		Subject DN:	C=US, O=Google, OU=Enterprise, CN=yubikey-svc@domain.com
		Issuer DN:	C=US, O=Google, OU=Enterprise, CN=Enterprise Subordinate CA
		Fingerprint:	dc4ea638c324cd259bb20ea42a5e4529aacc11d7f6835bf60cb533b9ba7a2d51
		Not Before:	Dec 12 16:36:00 2020 GMT
		Not After:	Dec 12 16:36:00 2022 GMT
	PIN tries left:	3
```


Once you have that,  create a test JWT and verify it with an RSA key that is extracted from a TPM and also directly. 

```log
# cd examples/
# go run main.go 
TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiY2RlZmciLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2OTMxMzUxMDEsImlzcyI6InRlc3QifQ.m2piHlp09fSbSR3nN0ca2JXu6TmnfDu-WCe9ZwpLlPb9dmKRmThSsbTRD7HL3mhGpez1fImWMCjnOtiIqxNxPe37HyuDnqUKJ3ei2EIGX0bNFzt95fnkNIIWr_4ug09CimmZaQ5P2Bp97-_ghIHVAXmTEtPnhtu8DappFo95mTP4asUhItYTI3elFjVpBzr9eoVr_7-JoI8BLMPIuhdwz3mx0bIjdQ63pYl6QgWq87-PpiTxvycstafLFla0n-uhF3qSjunUSG9N-jjgBmUPS7DL_mB5vygQ0OGxjDIfoNRxBv9nSUqS3LJO9L49be03t--UcSOhY51bTA-Xo7kgew
2023/08/27 07:17:21      verified with YK PublicKey
2023/08/27 07:17:21      verified with exported PubicKey

```

The JWT is formatted as:

```json
{
  "alg": "RS256",
  "kid": "abcdefg",
  "typ": "JWT"
}
{
  "exp": 1693135101,
  "iss": "test"
}
```

to use, just import the library (`"github.com/salrashid123/golang-jwt-yubikey"`) configure the Yubikey with the pin.  Remember to set the override so that the correct `alg` is defined in the JWT header

```golang
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	yk "github.com/salrashid123/golang-jwt-yubikey"
)

var ()

func main() {

	ctx := context.Background()

	var keyctx interface{}
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Issuer:    "test",
	}

	yk.SigningMethodYKRS256.Override()
	token := jwt.NewWithClaims(yk.SigningMethodYKRS256, claims)

	config := &yk.YKConfig{
		Pin: "123456",
	}

	keyctx, err := yk.NewYKContext(ctx, config)
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}

	token.Header["kid"] = config.GetKeyID()
	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	fmt.Printf("TOKEN: %s\n", tokenString)

	// verify with TPM based publicKey
	keyFunc, err := yk.YKVerfiyKeyfunc(ctx, config)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("     verified with TPM PublicKey")
	}

	// verify with provided RSAPublic key
	pubKey := config.GetPublicKey()

	v, err := jwt.Parse(vtoken.Raw, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}

}
```