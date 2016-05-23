package main

import (
	"crypto/sha256"
	"github.com/gorilla/mux"
	"github.com/pagedegeek/himitsu"
	"github.com/pagedegeek/himitsu/crypto_engine"
	"github.com/pagedegeek/himitsu/data_access"
	"github.com/pagedegeek/himitsu/password_derivation"
	"github.com/pagedegeek/himitsu/salt_generation"
	"github.com/pagedegeek/himitsu/uuid_generation"
	"log"
	"net/http"
)

var (
	h *himitsu.Himitsu
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

	h = himitsu.NewHimitsu(saltGenerator, uuidGenerator, pwdDerivator,
		cryptoEngine, dataAccess)

	router := mux.NewRouter()
	router.HandleFunc("/repositories", handleCreateRepository).
		Methods("POST", "PUT")
	router.HandleFunc("/secrets", handleCreateSecret).
		Methods("POST", "PUT")
	router.HandleFunc("/secrets", handleListSecrets).
		Methods("GET")
	router.HandleFunc("/secrets/{secret_name}", handleReadSecret).
		Methods("GET")

	certFile := "../public_key"
	keyFile := "../private_key"
	server := http.Server{Addr: ":8443", Handler: router}
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatal("Can't start server: %s", err.Error())
		return
	}
}
