package crypto_engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

type AESCFBEngine struct {
}

func NewAESCFBEngine() *AESCFBEngine {
	return &AESCFBEngine{}
}

/*
	cipher message composition:
	[HMAC(32 bits)|IV(16 bits)|CIPHERMSG]
*/

func (e *AESCFBEngine) Encrypt(msg, key, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		errMsg := "initialization vector length != AES block"
		return nil, fmt.Errorf(errMsg)
	}

	lenIV := aes.BlockSize
	ciphermsg := make([]byte, lenIV+len(msg))
	copy(ciphermsg[:lenIV], iv)

	encrypter := cipher.NewCFBEncrypter(c, iv)
	msg2 := make([]byte, len(msg))
	encrypter.XORKeyStream(msg2, msg)
	copy(ciphermsg[lenIV:], msg2)

	hm := hmac.New(sha256.New, key)
	hm.Write(ciphermsg)
	hmacSum := hm.Sum(nil)
	r := make([]byte, len(hmacSum)+len(ciphermsg))
	copy(r[:len(hmacSum)], hmacSum)
	copy(r[len(hmacSum):], ciphermsg)

	return r, nil
}

const (
	lenHmacSum int = 32
)

func (e *AESCFBEngine) Decrypt(cipherData, key []byte) ([]byte, error) {
	// message composition:
	// HMAC(32 bits)|IV(16bits)|CIPHERMSG
	msgHmacSum := cipherData[:lenHmacSum]
	ciphermsg := cipherData[lenHmacSum:]

	hm := hmac.New(sha256.New, key)
	hm.Write(ciphermsg)
	expectedMAC := hm.Sum(nil)
	if !hmac.Equal(expectedMAC, msgHmacSum) {
		return nil, fmt.Errorf("Invalid HMAC")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphermsg) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphermsg[:aes.BlockSize]
	ciphermsg = ciphermsg[aes.BlockSize:]

	decrypter := cipher.NewCFBDecrypter(c, iv)
	msg := make([]byte, len(ciphermsg))
	decrypter.XORKeyStream(msg, ciphermsg)

	return msg, nil
}

func (e *AESCFBEngine) Close() error {
	return nil
}
