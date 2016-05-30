package himitsu

type SaltGenerator interface {
	Call(size int) ([]byte, error)
	Close() error
}
