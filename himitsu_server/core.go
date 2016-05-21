package main

import (
	"crypto/sha256"
	"github.com/pagedegeek/himitsu"
	"github.com/pagedegeek/himitsu/crypto_engine"
	"github.com/pagedegeek/himitsu/data_access"
	"github.com/pagedegeek/himitsu/password_derivation"
	"github.com/pagedegeek/himitsu/salt_generation"
	"github.com/pagedegeek/himitsu/uuid_generation"
	"log"
)

func main() {
	saltGenerator := salt_generation.NewDefaultSaltGenerator()
	uuidGenerator := uuid_generation.NewDefaultUUIDGenerator()
	pwdDerivator := password_derivation.NewPBKDF2PasswordDerivator(
		32, 10000, sha256.New)
	cryptoEngine := crypto_engine.NewAESCFBEngine()
	dataAccess, err := data_access.NewDefaultDataAccess("/tmp/himitsu.bin")
	if err != nil {
		log.Fatal(err)
	}

	himitsu := himitsu.NewHimitsu(
		saltGenerator,
		uuidGenerator,
		pwdDerivator,
		cryptoEngine,
		dataAccess)

	repoUUID, userAccountUUID, err := himitsu.CreateRepository(
		"main", "sam", "foobarbaz")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Repository uuid: %s", repoUUID)
	log.Printf("user uuid: %s", userAccountUUID)

	// repoUUID := "48aa8e49-59d0-477b-a6f7-597081731b6c"
	// userAccountUUID := "c1366365-7333-472f-928f-ea2a861776dd"

	secret, err := himitsu.ReadSecret(
		repoUUID, userAccountUUID, "foobarbaz", "hello")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("secret: %s", secret)
}
