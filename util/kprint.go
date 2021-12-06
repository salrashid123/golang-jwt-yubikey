// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"crypto/sha256"
	"crypto/x509"
	"flag"

	"log"

	"github.com/go-piv/piv-go/piv"
	"github.com/lestrrat-go/jwx/jwk"
)

const ()

var ()

var (
	pin  = flag.String("pin", "123456", "Yubikey PIN")
	slog = flag.String("slot", "9c", "Yubikey slot")
)

func main() {

	flag.Parse()
	log.Printf("======= Init  ========")

	cards, err := piv.Cards()
	if err != nil {
		log.Fatalf("unable to open yubikey %v", err)
	}
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				log.Fatalf("could not find yubikey:  %v", err)
			}
			break
		}
	}
	if yk == nil {
		log.Fatalf("yubikey not found Please make sure the key is inserted %v", err)
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		log.Fatalf("unable to load certificate not found %v", err)
	}
	kPublicKey := cert.PublicKey

	akBytes, err := x509.MarshalPKIXPublicKey(kPublicKey)
	if err != nil {
		log.Fatalf("Unable to convert ekpub: %v", err)
	}

	rakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	log.Printf("     PublicKey: \n%v", string(rakPubPEM))

	jkey, err := jwk.New(kPublicKey)
	if err != nil {
		log.Fatalf("failed to create symmetric key: %s\n", err)
	}

	message := []byte(cert.Raw)
	hasher := sha256.New()
	hasher.Write(message)

	kid := hex.EncodeToString(hasher.Sum(nil))

	jkey.Set(jwk.KeyIDKey, kid)

	buf, err := json.MarshalIndent(jkey, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal key into JSON: %s\n", err)
		return
	}
	fmt.Printf("JWK Format:\n%s\n", buf)

}
