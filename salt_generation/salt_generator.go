package salt_generation

type SaltGenerator interface {
	Call(size int) ([]byte, error)
	Close() error
}
