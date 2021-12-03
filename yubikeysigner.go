package tpmjwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	jwt "github.com/golang-jwt/jwt"

	"github.com/go-piv/piv-go/piv"
)

type YKConfig struct {
	KeyID           string
	Pin             string
	Slot            string
	publicKeyFromYK crypto.PublicKey
}

type ykConfigKey struct{}

func (k *YKConfig) GetKeyID() string {
	return k.KeyID
}

func (k *YKConfig) GetPublicKey() crypto.PublicKey {
	return k.publicKeyFromYK
}

var (
	SigningMethodYKRS128 *SigningMethodYK
	SigningMethodYKRS256 *SigningMethodYK
	errMissingConfig     = errors.New("yk: missing configuration in provided context")
	errMissingYK         = errors.New("yk: YK device not available")
)

type SigningMethodYK struct {
	alg      string
	override jwt.SigningMethod
	hasher   crypto.Hash
}

func NewYKContext(parent context.Context, val *YKConfig) (context.Context, error) {

	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("unable to open yubikey %v", err)
	}
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return nil, fmt.Errorf("could not find yubikey:  %v", err)
			}
			break
		}
	}
	if yk == nil {
		return nil, fmt.Errorf("yubikey not found Please make sure the key is inserted %v", err)
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return nil, fmt.Errorf("unable to load certificate not found %v", err)
	}
	val.publicKeyFromYK = cert.PublicKey

	message := []byte(cert.Raw)
	hasher := sha256.New()
	hasher.Write(message)

	kid := hex.EncodeToString(hasher.Sum(nil))

	val.KeyID = kid

	return context.WithValue(parent, ykConfigKey{}, val), nil
}

// KMSFromContext extracts a KMSConfig from a context.Context
func YKFromContext(ctx context.Context) (*YKConfig, bool) {
	val, ok := ctx.Value(ykConfigKey{}).(*YKConfig)
	return val, ok
}

func init() {
	// RS256
	SigningMethodYKRS256 = &SigningMethodYK{
		"YKRS256",
		jwt.SigningMethodRS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodYKRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodYKRS256
	})
}

// Alg will return the JWT header algorithm identifier this method is configured for.
func (s *SigningMethodYK) Alg() string {
	return s.alg
}

// Override will override the default JWT implementation of the signing function this Cloud KMS type implements.
func (s *SigningMethodYK) Override() {
	s.alg = s.override.Alg()
	jwt.RegisterSigningMethod(s.alg, func() jwt.SigningMethod {
		return s
	})
}

func (s *SigningMethodYK) Hash() crypto.Hash {
	return s.hasher
}

func (s *SigningMethodYK) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}
	config, ok := YKFromContext(ctx)
	if !ok {
		return "", errMissingConfig
	}

	cards, err := piv.Cards()
	if err != nil {
		return "", fmt.Errorf("unable to open yubikey %v", err)
	}
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return "", fmt.Errorf("could not find yubikey:  %v", err)
			}
			break
		}
	}
	if yk == nil {
		return "", fmt.Errorf("yubikey not found Please make sure the key is inserted %v", err)
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return "", fmt.Errorf("unable to load certificate not found %v", err)
	}

	auth := piv.KeyAuth{PIN: config.Pin} //piv.DefaultPIN
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return "", fmt.Errorf("unable to load privateKey %v", err)
	}

	message := []byte(signingString)
	hasher := sha256.New()
	_, err = hasher.Write(message)
	if err != nil {
		return "", fmt.Errorf("error hashing YubiKey: %v", err)
	}

	hashed := hasher.Sum(message[:0])

	rng := rand.Reader

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("expected private key to implement crypto.Signer")
	}

	signedBytes, err := signer.Sign(rng, hashed, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf(" error from signing from YubiKey: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(signedBytes), nil
}

func YKVerfiyKeyfunc(ctx context.Context, config *YKConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.publicKeyFromYK, nil
	}, nil
}

func (s *SigningMethodYK) Verify(signingString, signature string, key interface{}) error {
	return s.override.Verify(signingString, signature, key)
}
