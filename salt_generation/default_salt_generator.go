package salt_generation

import (
	"crypto/rand"
	"io"
)

type DefaultSaltGenerator struct{}

func NewDefaultSaltGenerator() *DefaultSaltGenerator {
	return &DefaultSaltGenerator{}
}

func (dsg *DefaultSaltGenerator) Call(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	return salt, nil
}

func (dsg *DefaultSaltGenerator) Close() error {
	return nil
}
