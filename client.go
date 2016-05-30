package himitsu

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/pbkdf2"
)

var (
	uuidGenerator = NewDefaultUUIDGenerator()
	saltGenerator = NewDefaultSaltGenerator()
	cryptoEngine  = NewAESCFBEngine()
)

func SaveUserToFile(u *User, fileName string) error {
	blob, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, blob, 0644)
}

func LoadUserFromFile(fileName string) (*User, error) {
	blob, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var u User
	if err := json.Unmarshal(blob, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func buildUserKey(password string, salt []byte) []byte {
	// 32 = 256 bits = AES-256
	return pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)
}

func generateRSAKey(size int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, size)
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func generateUserKeySalt() ([]byte, error) {
	return saltGenerator.Call(32)
}

func encodeUserPublicKey(pubKey *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return string(pubBytes), nil
}

func encodeUserPrivateKey(privKey *rsa.PrivateKey) []byte {
	privASN1 := x509.MarshalPKCS1PrivateKey(privKey)
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	})
	return privBytes
}

func generateUserPrivateKeyIV() ([]byte, error) {
	return saltGenerator.Call(16) // 16 AES cipher block size
}

func encryptAndEncodeUserPrivateKey(privKey *rsa.PrivateKey, userKey []byte) (string, error) {
	userPrivateKeyIV, err := generateUserPrivateKeyIV()
	if err != nil {
		return "", err
	}

	encodedPrivKey := encodeUserPrivateKey(privKey)

	cipherUserPrivateKey, err := cryptoEngine.Encrypt(encodedPrivKey,
		userKey, userPrivateKeyIV)
	if err != nil {
		return "", err
	}

	return base64Encode(cipherUserPrivateKey), nil
}

func CreateUser(email, password string) (*User, error) {
	u := &User{Email: email}

	userPrivateKey, err := generateRSAKey(2048)
	if err != nil {
		return nil, err
	}

	userKeySalt, err := generateUserKeySalt()
	if err != nil {
		return nil, err
	}
	userKey := buildUserKey(password, userKeySalt)
	u.UserKeySalt = base64Encode(userKeySalt)

	u.PubKey, err = encodeUserPublicKey(&userPrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	u.CipherPrivateKey, err = encryptAndEncodeUserPrivateKey(userPrivateKey, userKey)
	if err != nil {
		return nil, err
	}

	// TODO: reset privkey in memory, etc.

	u.UUID = uuidGenerator.Call()

	// ciphertext, err := rsa.EncryptPKCS1v15(
	// 	rand.Reader,
	// 	&userPrivateKey.PublicKey,
	// 	[]byte("Hello World !"),
	// )
	// if err != nil {
	// 	return nil, err
	// }

	return u, nil
}

func GetUserPrivateKey(u *User, password string) (*rsa.PrivateKey, error) {
	userKeySalt, err := base64Decode(u.UserKeySalt)
	if err != nil {
		return nil, err
	}
	userKey := buildUserKey(password, userKeySalt)

	cipherPrivKey, err := base64Decode(u.CipherPrivateKey)
	if err != nil {
		return nil, err
	}

	pemPrivKey, err := cryptoEngine.Decrypt(cipherPrivKey, userKey)
	if err != nil {
		return nil, err
	}

	der, _ := pem.Decode(pemPrivKey)

	pk, err := x509.ParsePKCS1PrivateKey(der.Bytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func GetPublicKey(u *User) (*rsa.PublicKey, error) {
	der, _ := pem.Decode([]byte(u.PubKey))
	pubKey, err := x509.ParsePKIXPublicKey(der.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey.(*rsa.PublicKey), nil
}

// return ciphersecret, ciphersecretkey, error
func CreateSecret(name string, secret []byte, users []*User) (*Secret, error) {
	s := &Secret{
		UUID:             uuidGenerator.Call(),
		Name:             name,
		CipherSecretKeys: make(map[string]string),
	}

	// generate random key
	secretKey, err := saltGenerator.Call(32) // 32 = 256 bits = AES-256 key size
	if err != nil {
		return nil, err
	}

	// Encrypt secret with secretKey
	iv, err := saltGenerator.Call(16)
	if err != nil {
		return nil, err
	}
	cipherSecret, err := cryptoEngine.Encrypt(secret, secretKey, iv)
	if err != nil {
		return nil, err
	}
	s.CipherSecret = base64Encode(cipherSecret)

	// associate public keys
	for _, u := range users {
		// TODO: use goroutine
		pubKey, err := GetPublicKey(u)
		if err != nil {
			return nil, err
		}
		cipherSecretKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, secretKey)
		if err != nil {
			return nil, err
		}
		s.CipherSecretKeys[u.UUID] = base64Encode(cipherSecretKey)
	}

	return s, nil
}

func GetSecretContent(s *Secret, u *User, password string) ([]byte, error) {
	encodedCipherSecretKey, exists := s.CipherSecretKeys[u.UUID]
	if !exists {
		return nil, fmt.Errorf("secret %s not shared with user %s", s.UUID, u.UUID)
	}

	privKey, err := GetUserPrivateKey(u, password)
	if err != nil {
		return nil, err
	}

	cipherSecretKey, err := base64Decode(encodedCipherSecretKey)
	if err != nil {
		return nil, err
	}

	secretKey, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, cipherSecretKey)
	if err != nil {
		return nil, err
	}

	cipherSecret, err := base64Decode(s.CipherSecret)
	if err != nil {
		return nil, err
	}
	secret, err := cryptoEngine.Decrypt(cipherSecret, secretKey)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

func SaveSecretToFile(s *Secret, fileName string) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, blob, 0644)
}

func LoadSecretFromFile(fileName string) (*Secret, error) {
	blob, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var s Secret
	if err := json.Unmarshal(blob, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
