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
	"reflect"
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

func Zero(in []byte) {
	for i := 0; i < 1000; i++ {

		for i := 0; i < len(in); i++ {
			in[i] = 0x00
		}

		for i := 0; i < len(in); i++ {
			in[i] = 0xFF
		}
	}
}

func Clear(v interface{}) {
	p := reflect.ValueOf(v).Elem()
	p.Set(reflect.Zero(p.Type()))
}

func (h *Himitsu) loadRepositoryKey(userUUID, userPwd string) ([]byte, error) {
	userSalt, err := h.dataAccess.ReadUserAccountSalt(userUUID)
	if err != nil {
		return nil, err
	}

	derivedUserPwd := h.passwordDerivator.Call([]byte(userPwd), userSalt)
	defer Zero(derivedUserPwd)

	cipherRepoKey, err := h.dataAccess.ReadCipherRepositoryKey(userUUID)
	if err != nil {
		return nil, err
	}

	repoKey, err := h.cryptoEngine.Decrypt(cipherRepoKey, derivedUserPwd)
	if err != nil {
		return nil, err
	}
	return repoKey, nil
}

func (h *Himitsu) loadRepository(
	repoUUID string, repoKey []byte) (*Repository, error) {

	cipherRepo, err := h.dataAccess.ReadCipherRepository(repoUUID)
	if err != nil {
		return nil, err
	}

	encodedRepo, err := h.cryptoEngine.Decrypt(cipherRepo, repoKey)
	if err != nil {
		return nil, err
	}
	defer Zero(encodedRepo)

	b := bytes.NewBuffer(encodedRepo)
	defer b.Reset()
	repository := &Repository{}

	dec := gob.NewDecoder(b)
	if err := dec.Decode(repository); err != nil {
		return nil, err
	}

	return repository, nil
}

func (h *Himitsu) WriteSecret(
	repoUUID, userUUID, userPwd, secretName string, secretValue []byte) error {

	repoKey, err := h.loadRepositoryKey(userUUID, userPwd)
	if err != nil {
		return err
	}
	defer Zero(repoKey)

	repository, err := h.loadRepository(repoUUID, repoKey)
	if err != nil {
		return err
	}
	defer func() {
		Clear(repository)
		repository = nil
	}()

	if err := repository.WriteSecret(userUUID, secretName, secretValue); err != nil {
		return err
	}

	return h.saveRepository(repository, repoKey)
}

func (h *Himitsu) ReadSecret(
	repoUUID, userUUID, userPwd, secretName string) ([]byte, error) {

	repoKey, err := h.loadRepositoryKey(userUUID, userPwd)
	if err != nil {
		return nil, err
	}
	defer Zero(repoKey)

	repository, err := h.loadRepository(repoUUID, repoKey)
	if err != nil {
		return nil, err
	}
	defer func() {
		Clear(repository)
		repository = nil
	}()

	return repository.ReadSecret(userUUID, secretName)
}

func (h *Himitsu) ListSecretNames(
	repoUUID, userUUID, userPwd string) ([]string, error) {

	repoKey, err := h.loadRepositoryKey(userUUID, userPwd)
	if err != nil {
		return nil, err
	}
	defer Zero(repoKey)

	repository, err := h.loadRepository(repoUUID, repoKey)
	if err != nil {
		return nil, err
	}
	defer func() {
		Clear(repository)
		repository = nil
	}()

	return repository.ListSecretNames(userUUID)
}

func (h *Himitsu) CreateRepository(
	repoLabel, userLabel, userPwd string) (string, string, error) {

	userAccountSalt, err := h.saltGenerator.Call(32)
	if err != nil {
		return "", "", err
	}

	admin := &UserAccount{
		UUID:                 h.uuidGenerator.Call(),
		Label:                userLabel,
		CanReadSecret:        true,
		CanWriteSecret:       true,
		CanAdminUserAccounts: true}

	err = h.dataAccess.SaveUserAccountSalt(admin.UUID, userAccountSalt)
	if err != nil {
		return "", "", err
	}

	repo := &Repository{
		UUID:         h.uuidGenerator.Call(),
		Label:        repoLabel,
		UserAccounts: map[string]*UserAccount{admin.UUID: admin},
		Secrets:      make(map[string][]byte)}

	defer func() {
		Clear(repo)
		repo = nil
	}()

	repo.Secrets["hello"] = []byte("Hello World !")

	repositoryKey, err := h.saltGenerator.Call(32)
	if err != nil {
		return "", "", err
	}
	defer Zero(repositoryKey)

	derivedUserPwd := h.passwordDerivator.Call(
		[]byte(userPwd), userAccountSalt)
	defer Zero(derivedUserPwd)

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

	if err := h.saveRepository(repo, repositoryKey); err != nil {
		return "", "", err
	}

	return repo.UUID, admin.UUID, nil
}

func (h *Himitsu) saveRepository(
	repository *Repository, repositoryKey []byte) error {

	var encodedRepository bytes.Buffer
	defer encodedRepository.Reset()
	enc := gob.NewEncoder(&encodedRepository)
	if err := enc.Encode(repository); err != nil {
		return err
	}

	repositoryIV, err := h.saltGenerator.Call(16)
	if err != nil {
		return err
	}
	cipherRepository, err := h.cryptoEngine.Encrypt(
		encodedRepository.Bytes(), repositoryKey, repositoryIV)
	if err != nil {
		return err
	}

	return h.dataAccess.SaveCipherRepository(
		repository.UUID, cipherRepository)
}

type Repository struct {
	UUID         string                  `json:"uuid"`
	Label        string                  `json:"label"`
	UserAccounts map[string]*UserAccount `json:"user_accounts"`
	Secrets      map[string][]byte       `json:"secrets"`
}

const (
	RIGHT_READ_SECRET  string = "ReadSecret"
	RIGHT_WRITE_SECRET string = "WriteSecret"
)

type ErrUnknownRight struct {
	rightName string
}

func (e *ErrUnknownRight) Error() string {
	return fmt.Sprintf("Unknown right '%s'", e.rightName)
}

type ErrUserAccountHasNoRight struct {
	userUUID  string
	rightName string
}

func (e *ErrUserAccountHasNoRight) Error() string {
	return fmt.Sprintf("UserAccount '%s' has no right '%s'",
		e.userUUID, e.rightName)
}

func (r *Repository) checkRight(
	userAccount *UserAccount, rightName string) (err error) {
	var userHasRight bool = false

	switch rightName {
	case RIGHT_READ_SECRET:
		userHasRight = userAccount.CanReadSecret
	case RIGHT_WRITE_SECRET:
		userHasRight = userAccount.CanWriteSecret
	default:
		return &ErrUnknownRight{rightName: rightName}
	}

	if userHasRight {
		return nil
	}
	return &ErrUserAccountHasNoRight{
		userUUID: userAccount.UUID, rightName: rightName}
}

func (r *Repository) findUserAccount(userUUID string) (*UserAccount, error) {
	userAccount, exists := r.UserAccounts[userUUID]
	if !exists {
		return nil, fmt.Errorf("UserAccount '%s' not exists", userUUID)
	}
	return userAccount, nil
}

type ErrUnknownSecret struct {
	secretName string
}

func (e *ErrUnknownSecret) Error() string {
	return fmt.Sprintf("Secret '%s' not found", e.secretName)
}

func (r *Repository) ReadSecret(userUUID, secretName string) ([]byte, error) {
	userAccount, err := r.findUserAccount(userUUID)
	if err != nil {
		return nil, err
	}

	if err := r.checkRight(userAccount, RIGHT_READ_SECRET); err != nil {
		return nil, err
	}

	secret, exists := r.Secrets[secretName]
	if !exists {
		return nil, &ErrUnknownSecret{secretName: secretName}
	}
	return secret, nil
}

func (r *Repository) ListSecretNames(userUUID string) ([]string, error) {
	userAccount, err := r.findUserAccount(userUUID)
	if err != nil {
		return nil, err
	}

	if err := r.checkRight(userAccount, RIGHT_READ_SECRET); err != nil {
		return nil, err
	}

	secretNames := make([]string, 0)
	for k, _ := range r.Secrets {
		secretNames = append(secretNames, k)
	}

	return secretNames, nil
}

func (r *Repository) WriteSecret(
	userUUID, secretName string, secretValue []byte) error {

	userAccount, err := r.findUserAccount(userUUID)
	if err != nil {
		return err
	}

	if err := r.checkRight(userAccount, RIGHT_WRITE_SECRET); err != nil {
		return err
	}

	r.Secrets[secretName] = secretValue

	return nil
}

type UserAccount struct {
	UUID                 string `json:"uuid"`
	Label                string `json:"label"`
	CanReadSecret        bool   `json:"can_read_secret"`
	CanWriteSecret       bool   `json:"can_write_secret"`
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
