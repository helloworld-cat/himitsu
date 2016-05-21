package salt_generation

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	assert := assert.New(t)
	var g SaltGenerator = NewDefaultSaltGenerator()

	salt, err := g.Call(32)
	assert.Nil(err)
	assert.NotNil(salt)

	salt2, err2 := g.Call(32)
	assert.Nil(err2)
	assert.NotNil(salt2)
	assert.NotEqual(salt2, salt)
	assert.Nil(g.Close())
}

func Test250000UniqSalts(t *testing.T) {
	count := 250000
	assert := assert.New(t)
	g := NewDefaultSaltGenerator()
	defer g.Close()

	m := make(map[string]bool)
	for i := 0; i < count; i++ {
		salt, err := g.Call(5)
		assert.Nil(err)
		k := base64.StdEncoding.EncodeToString(salt)
		m[k] = true
	}

	assert.Equal(count, len(m))
}
