package himitsu

import (
	"github.com/satori/go.uuid"
)

type DefaultUUIDGenerator struct{}

func NewDefaultUUIDGenerator() *DefaultUUIDGenerator {
	return &DefaultUUIDGenerator{}
}

func (dug *DefaultUUIDGenerator) Call() string {
	return uuid.NewV4().String()
}

func (dug *DefaultUUIDGenerator) Close() error {
	return nil
}
