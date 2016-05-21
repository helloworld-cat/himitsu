package password_derivation

import (
	"golang.org/x/crypto/pbkdf2"
	"hash"
)

type PBKDF2PasswordDerivator struct {
	keyLen   int
	iter     int
	hashFunc func() hash.Hash
}

func NewPBKDF2PasswordDerivator(keyLen int, iter int,
	hf func() hash.Hash) *PBKDF2PasswordDerivator {

	return &PBKDF2PasswordDerivator{
		keyLen:   keyLen,
		iter:     iter,
		hashFunc: hf,
	}
}

func (pd *PBKDF2PasswordDerivator) Call(pwd, salt []byte) []byte {
	return pbkdf2.Key(pwd, salt, pd.iter, pd.keyLen, pd.hashFunc)
}

func (pd *PBKDF2PasswordDerivator) Close() error {
	return nil
}
