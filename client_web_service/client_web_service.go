package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/pagedegeek/himitsu"
	"log"
	"net/http"
)

func main() {
	router := mux.NewRouter()
	router.Handle("/", logHandler(handleIndex))
	router.Handle("/user_accounts", logHandler(handleCreateUser)).
		Methods("POST")
	router.Handle("/secrets", logHandler(handleCreateSecret)).
		Methods("POST")

	certFile := "../public_key"
	keyFile := "../private_key"
	server := http.Server{Addr: ":8443", Handler: router}
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatal("Can't start server: %s", err.Error())
		return
	}
}

type (
	appHandler func(http.ResponseWriter, *http.Request) (int, error)
)

func logHandler(h appHandler) http.Handler {
	fn := func(rw http.ResponseWriter, req *http.Request) {
		log.Printf("%s %s", req.RemoteAddr, req.URL.Path)
		if statusCode, err := h(rw, req); err != nil {
			log.Printf("handle error: %d, %s", statusCode, err.Error())
			rw.WriteHeader(statusCode)
			rw.Write([]byte(err.Error()))
			return
		}
	}
	return http.HandlerFunc(fn)

}

func handleIndex(rw http.ResponseWriter, req *http.Request) (int, error) {
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Hello World !"))
	return 0, nil
}

func handleCreateUser(rw http.ResponseWriter, req *http.Request) (int, error) {
	email := "foo@bar.com"
	password := "foobar"
	u, err := himitsu.CreateUser(email, password)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	fileName := fmt.Sprintf("/tmp/%s.json", u.UUID)

	if err := himitsu.SaveUserToFile(u, fileName); err != nil {
		return http.StatusInternalServerError, err
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(u.UUID))

	// ua2, err := himitsuClient.NewUserAccountFromFile(fmt.Sprintf("/tmp/%s.json", ua.UUID))
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// pk, err := himitsuClient.GetUserAccountPrivateKey(ua2, password)
	// if err != nil {
	// 	return http.StatusInternalServerError, err
	// }
	//
	// text, err := rsa.DecryptPKCS1v15(rand.Reader, pk, ciphertext)
	// if err != nil {
	// 	return http.StatusInternalServerError, err
	// }
	// log.Printf("%s", string(text))

	return 0, nil
}

func handleCreateSecret(rw http.ResponseWriter, req *http.Request) (int, error) {
	email := "foo@bar.com"
	password := "foobar"
	u, err := himitsu.CreateUser(email, password)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	s, err := himitsu.CreateSecret("hello-secret", []byte("Hello World !"), []*himitsu.User{u})
	if err != nil {
		return http.StatusInternalServerError, err
	}

	fileName := fmt.Sprintf("/tmp/secret_%s.json", s.UUID)
	if err := himitsu.SaveSecretToFile(s, fileName); err != nil {
		return http.StatusInternalServerError, err
	}

	s2, err := himitsu.LoadSecretFromFile(fileName)
	if err := himitsu.SaveSecretToFile(s, fileName); err != nil {
		return http.StatusInternalServerError, err
	}

	secretContent, err := himitsu.GetSecretContent(s2, u, password)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(secretContent))

	return 0, nil
}
