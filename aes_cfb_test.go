package himitsu

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	hexKey string = "c80433215701adb3fe6e3fe17a3d438b5f209b9" +
		"494fc10c4e486ecb054c925e0"
	hexIV   string = "c80433215701adb3fe6e3fe17a3d438b"
	hexHMAC string = "63c15f3e3b881b0a788f93676d625def" +
		"4d9d6a429766e41915deb2f58eae9053"
	hexCipherMsg string = "63c15f3e3b881b0a788f93676d625def" +
		"4d9d6a429766e41915deb2f58eae9053c80433215701ad" +
		"b3fe6e3fe17a3d438b4b16e706938b655a739c89cbd4"
	strPlainMsg string = "Hello World !"
)

var (
	key               []byte
	iv                []byte
	expectedCipherMsg []byte
	plainMsg          []byte
	hMac              []byte
	ce                CryptoEngine = NewAESCFBEngine()
	ciphermsg         []byte
)

func setup(t *testing.T) *assert.Assertions {
	assert := assert.New(t)

	assert.NotNil(ce)

	key, _ = hex.DecodeString(hexKey)
	assert.Equal(32, len(key))

	iv, _ = hex.DecodeString(hexIV)
	assert.Equal(16, len(iv))

	hMac, _ = hex.DecodeString(hexHMAC)
	assert.Equal(32, len(hMac))

	plainMsg = []byte(strPlainMsg)

	expectedCipherMsg, _ = hex.DecodeString(hexCipherMsg)

	return assert
}

func TestEncrypt(t *testing.T) {
	assert := setup(t)

	ciphermsg, err := ce.Encrypt(plainMsg, key, iv)
	assert.Nil(err)

	assert.NotNil(ciphermsg)

	assert.Equal(expectedCipherMsg, ciphermsg)

	assert.Equal(hMac, ciphermsg[:32])

	assert.Equal(iv, ciphermsg[32:32+16])

	assert.Equal(len(plainMsg), len(ciphermsg[32+16:]))
}

func TestDecrypt(t *testing.T) {
	assert := setup(t)

	plainmsg, err := ce.Decrypt(expectedCipherMsg, key)
	assert.Nil(err)

	assert.NotNil(plainmsg)

	assert.Equal(plainMsg, plainmsg)
}

func TestEncryptDecrypt(t *testing.T) {
	assert := assert.New(t)

	key, err := hex.DecodeString(
		"aac0591c3adcb47a629d49f37a51e2d" +
			"995f3c8712efd37ca22515ca54acef1b8")
	assert.Nil(err)

	iv, err := hex.DecodeString("6ae2702ad53a2fb6a34e8747628a7d8b")
	assert.Nil(err)

	plainMsg1, _ := hex.DecodeString(
		"84e7daf6fe1665fa8007e120707d2e" +
			"280a4c17dd4ca13fcf53344448576e870e")

	ciphermsg, err := ce.Encrypt(plainMsg1, key, iv)
	assert.Nil(err)

	assert.Equal(iv, ciphermsg[32:32+16])
	assert.Equal(len(plainMsg1), len(ciphermsg[32+16:]))

	plainMsg2, err := ce.Decrypt(ciphermsg, key)
	assert.Nil(err)

	assert.Equal(plainMsg1, plainMsg2)
}
