package himitsu

type (
	Secret struct {
		UUID             string            `json:"uuid"`
		Name             string            `json:"name"`
		CipherSecret     string            `json:"cipher_secret"`
		CipherSecretKeys map[string]string `json:"cipher_secret_keys"`
	}
)
