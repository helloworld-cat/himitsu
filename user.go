package himitsu

type (
	User struct {
		UUID             string `json:"uuid"`
		Email            string `json:"email"`
		PubKey           string `json:"pub_key"`
		CipherPrivateKey string `json:"cipher_priv_key"`
		UserKeySalt      string `json:"user_key_salt"`
	}
)
