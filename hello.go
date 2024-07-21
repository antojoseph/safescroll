package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
)

// EllipticCurve data struct
type EllipticCurve struct {
	pubKeyCurve elliptic.Curve
	privateKey  *ecdsa.PrivateKey
	publicKey   *ecdsa.PublicKey
}

// New creates a new EllipticCurve instance
func New(curve elliptic.Curve) *EllipticCurve {
	return &EllipticCurve{
		pubKeyCurve: curve,
	}
}

// GenerateKeys generates a new key pair and returns the private and public keys
func (ec *EllipticCurve) GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(ec.pubKeyCurve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ec.privateKey = privKey
	ec.publicKey = &privKey.PublicKey
	return privKey, &privKey.PublicKey, nil
}

// EncodePrivate private key
func (ec *EllipticCurve) EncodePrivate(privKey *ecdsa.PrivateKey) (key string, err error) {

	encoded, err := x509.MarshalECPrivateKey(privKey)

	if err != nil {
		return
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})

	key = string(pemEncoded)

	return
}

// EncodePublic public key
func (ec *EllipticCurve) EncodePublic(pubKey *ecdsa.PublicKey) (key string, err error) {

	encoded, err := x509.MarshalPKIXPublicKey(pubKey)

	if err != nil {
		return
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

	key = string(pemEncodedPub)
	return
}

// LoadPrivateKey loads a private key from a PEM file
func (ec *EllipticCurve) LoadPrivateKey(filename string) error {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	ec.privateKey = privateKey
	ec.publicKey = &privateKey.PublicKey
	return nil
}

// LoadPublicKey loads a public key from a PEM file
func (ec *EllipticCurve) LoadPublicKey(filename string) error {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an ECDSA public key")
	}

	ec.publicKey = ecdsaPublicKey
	return nil
}

// SignMessage signs a message using the private key
func (ec *EllipticCurve) SignMessage(message string) (string, error) {
	if ec.privateKey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, ec.privateKey, hash[:])
	if err != nil {
		return "", err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(signature), nil
}

// VerifySignature verifies a signature for a given message
func (ec *EllipticCurve) VerifySignature(message, signatureHex string) (bool, error) {
	if ec.publicKey == nil {
		return false, fmt.Errorf("public key is nil")
	}

	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, err
	}

	sigLen := len(signatureBytes)
	r := new(big.Int).SetBytes(signatureBytes[:sigLen/2])
	s := new(big.Int).SetBytes(signatureBytes[sigLen/2:])

	hash := sha256.Sum256([]byte(message))
	return ecdsa.Verify(ec.publicKey, hash[:], r, s), nil
}

func main() {
	var operation string
	var privateKeyFile, publicKeyFile, message, signature string

	flag.StringVar(&operation, "op", "", "Operation to perform: sign, verify, or self-test")
	flag.StringVar(&privateKeyFile, "priv", "", "Path to the private key file (for signing)")
	flag.StringVar(&publicKeyFile, "pub", "", "Path to the public key file (for verifying)")
	flag.StringVar(&message, "message", "", "Message to sign or verify")
	flag.StringVar(&signature, "signature", "", "Signature to verify (for verify operation)")
	flag.Parse()

	if operation == "" {
		fmt.Println("Please specify an operation: -op sign|verify|self-test")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ec := New(elliptic.P256())

	switch operation {
	case "sign":
		if privateKeyFile == "" || message == "" {
			fmt.Println("For signing, please provide: -priv <private_key_file> -message <message_to_sign>")
			os.Exit(1)
		}
		err := ec.LoadPrivateKey(privateKeyFile)
		if err != nil {
			fmt.Println("Error loading private key:", err)
			os.Exit(1)
		}
		signature, err := ec.SignMessage(message)
		if err != nil {
			fmt.Println("Error signing message:", err)
			os.Exit(1)
		}
		fmt.Println("Message:", message)
		fmt.Println("Signature:", signature)

	case "verify":
		if publicKeyFile == "" || message == "" || signature == "" {
			fmt.Println("For verifying, please provide: -pub <public_key_file> -message <message> -signature <signature>")
			os.Exit(1)
		}
		err := ec.LoadPublicKey(publicKeyFile)
		if err != nil {
			fmt.Println("Error loading public key:", err)
			os.Exit(1)
		}
		isValid, err := ec.VerifySignature(message, signature)
		if err != nil {
			fmt.Println("Error verifying signature:", err)
			os.Exit(1)
		}
		fmt.Println("Signature is valid:", isValid)

	case "self-test":
		privKey, pubKey, err := ec.GenerateKeys()
		if err != nil {
			fmt.Println("Error generating keys:", err)
			os.Exit(1)
		}
		ecodedPrivKey, err := ec.EncodePrivate(privKey)
		if err != nil {
			fmt.Println("Error generating encodedPrivatekey:", err)
		}
		fmt.Printf("Private Key:%s,", ecodedPrivKey)
		ecodedPublicKey, err := ec.EncodePublic(pubKey)
		if err != nil {
			fmt.Println("Error generating encodedPublickey:", err)
		}
		fmt.Printf("Public Key:%s,", ecodedPublicKey)

		testMessage := "This is the message that will be signed for self-test"
		signature, err := ec.SignMessage(testMessage)
		if err != nil {
			fmt.Println("Error signing message:", err)
			os.Exit(1)
		}
		fmt.Println("Test Message:", testMessage)
		fmt.Println("Signature:", signature)
		isValid, err := ec.VerifySignature(testMessage, signature)
		if err != nil {
			fmt.Println("Error verifying signature:", err)
			os.Exit(1)
		}
		fmt.Println("Signature is valid:", isValid)

	default:
		fmt.Println("Invalid operation. Please use 'sign', 'verify', or 'self-test'.")
		os.Exit(1)
	}
}
