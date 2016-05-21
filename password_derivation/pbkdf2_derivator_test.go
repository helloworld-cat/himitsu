package password_derivation

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCall(t *testing.T) {
	pwd := []byte("secret password")
	salt := []byte("salt")
	assert := assert.New(t)

	var pd PasswordDerivator = NewPBKDF2PasswordDerivator(8, 100, sha256.New)
	assert.NotNil(pd)

	assert.NotNil(pd.Call(pwd, salt))
	expectedDerivatedPwd, _ := hex.DecodeString("44b8b1aa13d8c052")
	assert.Equal(expectedDerivatedPwd, pd.Call(pwd, salt))
	assert.Nil(pd.Close())
}
