package uuid_generation

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCall(t *testing.T) {
	assert := assert.New(t)

	var dug UUIDGenerator = NewDefaultUUIDGenerator()

	uuid1 := dug.Call()
	assert.NotNil(uuid1)

	uuid2 := dug.Call()
	assert.NotNil(uuid2)

	assert.NotEqual(uuid1, uuid2)

	assert.Nil(dug.Close())
}

func Test250000UniqUUIDs(t *testing.T) {
	assert := assert.New(t)

	count := 250000
	m := make(map[string]bool)

	dug := NewDefaultUUIDGenerator()
	defer dug.Close()

	for i := 0; i < count; i++ {
		u := dug.Call()
		m[u] = true
	}
	assert.Equal(count, len(m))
}
