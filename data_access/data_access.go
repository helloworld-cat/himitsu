package data_access

import (
	"fmt"
	"github.com/boltdb/bolt"
)

type DataAccess interface {
	Close() error

	SaveUserAccountSalt(userUUID string, userSalt []byte) error

	SaveCipherRepositoryKey(userUUID string, cipherRepositoryKey []byte) error
	SaveCipherRepository(repoUUID string, cipherRepo []byte) error

	ReadUserAccountSalt(userUUID string) ([]byte, error)

	ReadCipherRepositoryKey(userUUID string) ([]byte, error)
	ReadCipherRepository(repoUUID string) ([]byte, error)
}

type DefaultDataAccess struct {
	db *bolt.DB
}

const (
	bucketNameCipherRepositories   = "cipher_repositories"
	bucketNameCipherRepositoryKeys = "cipher_repository_keys"
	bucketNameUserAccountsSalts    = "user_accounts_salts"
)

func NewDefaultDataAccess(filename string) (*DefaultDataAccess, error) {
	db, err := bolt.Open(filename, 0600, nil)
	if err != nil {
		return nil, err
	}
	return &DefaultDataAccess{db: db}, nil
}

func (dda *DefaultDataAccess) ReadCipherRepository(
	repoUUID string) ([]byte, error) {
	return dda.read(
		bucketNameCipherRepositories, repoUUID)
}

func (dda *DefaultDataAccess) ReadCipherRepositoryKey(
	userUUID string) ([]byte, error) {
	return dda.read(
		bucketNameCipherRepositoryKeys, userUUID)
}

func (dda *DefaultDataAccess) ReadUserAccountSalt(
	userUUID string) ([]byte, error) {
	return dda.read(bucketNameUserAccountsSalts, userUUID)
}

func (dda *DefaultDataAccess) SaveUserAccountSalt(
	userUUID string, userSalt []byte) error {
	return dda.save(
		bucketNameUserAccountsSalts, userUUID, userSalt)
}

func (dda *DefaultDataAccess) SaveCipherRepositoryKey(
	userUUID string, cipherRepositoryKey []byte) error {
	return dda.save(
		bucketNameCipherRepositoryKeys, userUUID, cipherRepositoryKey)
}

func (dda *DefaultDataAccess) SaveCipherRepository(
	repoUUID string, cipherRepo []byte) error {
	return dda.save(
		bucketNameCipherRepositories, repoUUID, cipherRepo)
}

func (dda *DefaultDataAccess) Close() error {
	return dda.db.Close()
}

func (dda *DefaultDataAccess) read(bucketName, key string) ([]byte, error) {
	var value []byte
	err := dda.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return fmt.Errorf("Bucket '%s' not exists", bucketName)
		}
		value = b.Get([]byte(key))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (dda *DefaultDataAccess) save(bucketName, key string, value []byte) error {
	return dda.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), value)
	})
}
