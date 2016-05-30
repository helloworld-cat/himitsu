package himitsu

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestZero(t *testing.T) {
	assert := assert.New(t)

	msg := "Hello World !"
	v := []byte(msg)
	Zero(v, 1000)
	assert.NotEqual([]byte("Hello World !"), v)
}

func TestClear(t *testing.T) {
	assert := assert.New(t)
	v := struct {
		Foo string
		N   int
	}{
		Foo: "foo",
		N:   123,
	}
	assert.Equal("foo", v.Foo)
	assert.Equal(123, v.N)
	Clear(&v)
	assert.Equal("", v.Foo)
	assert.Equal(0, v.N)
}
