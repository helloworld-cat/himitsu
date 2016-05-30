package himitsu

type UUIDGenerator interface {
	Call() string
	Close() error
}
