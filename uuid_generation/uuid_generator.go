package uuid_generation

type UUIDGenerator interface {
	Call() string
	Close() error
}
