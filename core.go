package himitsu

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/pagedegeek/himitsu/crypto_engine"
	"github.com/pagedegeek/himitsu/data_access"
	"github.com/pagedegeek/himitsu/password_derivation"
	"github.com/pagedegeek/himitsu/salt_generation"
	"github.com/pagedegeek/himitsu/uuid_generation"
)

type Himitsu struct {
	saltGenerator     salt_generation.SaltGenerator
	uuidGenerator     uuid_generation.UUIDGenerator
	passwordDerivator password_derivation.PasswordDerivator
	cryptoEngine      crypto_engine.CryptoEngine
	dataAccess        data_access.DataAccess
}

func NewHimitsu(
	saltGenerator salt_generation.SaltGenerator,
	uuidGenerator uuid_generation.UUIDGenerator,
	passwordDerivator password_derivation.PasswordDerivator,
	cryptoEngine crypto_engine.CryptoEngine,
	dataAccess data_access.DataAccess) *Himitsu {

	return &Himitsu{
		saltGenerator:     saltGenerator,
		uuidGenerator:     uuidGenerator,
		passwordDerivator: passwordDerivator,
		cryptoEngine:      cryptoEngine,
		dataAccess:        dataAccess,
	}
}

func zero(in []byte) {
	for i := 0; i < len(in); i++ {
		in[i] = 0
	}
}

func (h *Himitsu) ReadSecret(
	repoUUID, userUUID, userPwd, secretName string) ([]byte, error) {

	userSalt, err := h.dataAccess.ReadUserAccountSalt(userUUID)
	if err != nil {
		return nil, err
	}

	derivedUserPwd := h.passwordDerivator.Call([]byte(userPwd), userSalt)
	defer zero(derivedUserPwd)

	cipherRepoKey, err := h.dataAccess.ReadCipherRepositoryKey(userUUID)
	if err != nil {
		return nil, err
	}

	repositoryKey, err := h.cryptoEngine.Decrypt(
		cipherRepoKey, derivedUserPwd)
	if err != nil {
		return nil, err
	}
	defer zero(repositoryKey)

	cipherRepository, err := h.dataAccess.ReadCipherRepository(repoUUID)
	if err != nil {
		return nil, err
	}

	encodedRepository, err := h.cryptoEngine.Decrypt(
		cipherRepository, repositoryKey)
	if err != nil {
		return nil, err
	}
	b := bytes.NewBuffer(encodedRepository)
	repository := &Repository{}
	defer zero(encodedRepository)

	dec := gob.NewDecoder(b)
	if err := dec.Decode(repository); err != nil {
		return nil, err
	}

	userAccount, exists := repository.UserAccounts[userUUID]
	if !exists {
		return nil, fmt.Errorf(
			"UserAccount '%s' not exists", userUUID)
	}

	if !userAccount.CanReadSecret {
		return nil, fmt.Errorf(
			"UserAccount has no right 'read secret'")
	}

	secret, exists := repository.Secrets[secretName]
	if !exists {
		return nil, fmt.Errorf("Secret '%s' not exists", secretName)
	}

	return secret, nil
}

func (h *Himitsu) CreateRepository(
	repoName, userName, userPwd string) (string, string, error) {

	userAccountSalt, err := h.saltGenerator.Call(32)
	if err != nil {
		return "", "", err
	}

	admin := &UserAccount{
		UUID:                 h.uuidGenerator.Call(),
		Name:                 userName,
		CanReadSecret:        true,
		CanCreateSecret:      true,
		CanUpdateSecret:      true,
		CanDeleteSecret:      true,
		CanAdminUserAccounts: true}

	err = h.dataAccess.SaveUserAccountSalt(admin.UUID, userAccountSalt)
	if err != nil {
		return "", "", err
	}

	repo := &Repository{
		UUID:         h.uuidGenerator.Call(),
		Name:         repoName,
		UserAccounts: map[string]*UserAccount{admin.UUID: admin},
		Secrets:      make(map[string][]byte)}

	repo.Secrets["hello"] = []byte("Hello World !")

	repositoryKey, err := h.saltGenerator.Call(32)
	if err != nil {
		return "", "", err
	}
	defer zero(repositoryKey)

	derivedUserPwd := h.passwordDerivator.Call(
		[]byte(userPwd), userAccountSalt)
	defer zero(derivedUserPwd)

	repositoryKeyIV, err := h.saltGenerator.Call(16)
	if err != nil {
		return "", "", err
	}
	cipherRepositoryKey, err := h.cryptoEngine.Encrypt(repositoryKey,
		derivedUserPwd, repositoryKeyIV)
	if err != nil {
		return "", "", err
	}

	if err := h.dataAccess.SaveCipherRepositoryKey(admin.UUID,
		cipherRepositoryKey); err != nil {
		return "", "", err
	}

	var encodedRepository bytes.Buffer
	enc := gob.NewEncoder(&encodedRepository)
	if err := enc.Encode(repo); err != nil {
		return "", "", err
	}

	repositoryIV, err := h.saltGenerator.Call(16)
	if err != nil {
		return "", "", err
	}
	cipherRepository, err := h.cryptoEngine.Encrypt(
		encodedRepository.Bytes(), repositoryKey, repositoryIV)
	if err != nil {
		return "", "", err
	}

	err = h.dataAccess.SaveCipherRepository(repo.UUID, cipherRepository)
	if err != nil {
		return "", "", err
	}

	return repo.UUID, admin.UUID, nil
}

type Repository struct {
	UUID         string                  `json:"uuid"`
	Name         string                  `json:"name"`
	UserAccounts map[string]*UserAccount `json:"user_accounts"`
	Secrets      map[string][]byte       `json:"secrets"`
}

type UserAccount struct {
	UUID                 string `json:"uuid"`
	Name                 string `json:"name"`
	CanReadSecret        bool   `json:"can_read_secret"`
	CanCreateSecret      bool   `json:"can_create_secret"`
	CanUpdateSecret      bool   `json:"can_update_secret"`
	CanDeleteSecret      bool   `json:"can_delete_secret"`
	CanAdminUserAccounts bool   `json:"can_admin_user_accounts"`
}

func (h *Himitsu) Close() error {
	if err := h.saltGenerator.Close(); err != nil {
		return err
	}

	if err := h.uuidGenerator.Close(); err != nil {
		return err
	}

	if err := h.passwordDerivator.Close(); err != nil {
		return err
	}

	if err := h.cryptoEngine.Close(); err != nil {
		return err
	}

	if err := h.dataAccess.Close(); err != nil {
		return err
	}

	return nil
}
