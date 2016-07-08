package gofident

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	"github.com/fortifi/fident/logging"
)

const fidentHeaderPrefix = "X-Fident"

var fidentPublicKey *rsa.PublicKey

// InitWithPubKeyPath Inits fident client library with fident public key
func InitWithPubKeyPath(pubKeyPath string) {
	key, err := loadFidentPublicKey(pubKeyPath)
	if err != nil {
		logging.WriteError(err, true)
	}
	fidentPublicKey = key
}

// Verify that request is signed by fident
func Verify(req *http.Request) bool {
	if fidentPublicKey == nil {
		return false
	}

	var keys []string
	for k := range req.Header {
		if strings.HasPrefix(k, fidentHeaderPrefix) && k != getFidentSignatureHeaderKey() {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	message := req.RequestURI
	for _, k := range keys {
		message += k + req.Header.Get(k)
	}
	hash := sha256.New()
	hash.Write([]byte(message))
	hashResult := hash.Sum(nil)
	sigEncoded := req.Header.Get(getFidentSignatureHeaderKey())
	rawSignature, err := base64.URLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return false
	}
	result := rsa.VerifyPKCS1v15(fidentPublicKey, crypto.SHA256, hashResult, rawSignature)

	if result == nil {
		return true
	}
	return false
}

func getFidentSignatureHeaderKey() string {
	return fidentHeaderPrefix + "-Signature"
}

// Loads fident public key into a memory
func loadFidentPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("No fident RSA key found")
	}

	publickey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Failed to parse public key")
	}

	rsaPubKey := publickey.(*rsa.PublicKey)
	return rsaPubKey, nil
}
