package crypto_engine

type CryptoEngine interface {
	Encrypt(msg []byte, key, iv []byte) ([]byte, error)
	Decrypt(ciphermsg []byte, key []byte) ([]byte, error)
	Close() error
}
