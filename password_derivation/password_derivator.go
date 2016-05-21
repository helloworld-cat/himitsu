package password_derivation

type PasswordDerivator interface {
	Call(pwd, salt []byte) []byte
	Close() error
}
