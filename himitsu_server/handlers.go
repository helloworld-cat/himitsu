package main

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/pagedegeek/himitsu"
	"log"
	"net/http"
)

func handleCreateRepository(rw http.ResponseWriter, req *http.Request) {
	repoLabel := req.URL.Query().Get("repo_label")
	userLabel := req.URL.Query().Get("user_label")
	userPwd := req.URL.Query().Get("user_pwd")

	repoUUID, userAccountUUID, err := h.CreateRepository(
		repoLabel, userLabel, userPwd)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}

	data := make(map[string]string)
	data["repository_label"] = repoLabel
	data["repository_uuid"] = repoUUID
	data["user_uuid"] = userAccountUUID

	blob, err := json.Marshal(data)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	rw.Write(blob)
}

func handleListSecrets(rw http.ResponseWriter, req *http.Request) {
	repoUUID := req.URL.Query().Get("repo_uuid")
	userUUID := req.URL.Query().Get("user_uuid")
	userPwd := req.URL.Query().Get("user_pwd")

	secretNames, err := h.ListSecretNames(repoUUID, userUUID, userPwd)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	blob, err := json.Marshal(secretNames)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	rw.Write(blob)
}

func handleReadSecret(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	secretName := vars["secret_name"]
	repoUUID := req.URL.Query().Get("repo_uuid")
	userUUID := req.URL.Query().Get("user_uuid")
	userPwd := req.URL.Query().Get("user_pwd")
	format := req.URL.Query().Get("format")

	secret, err := h.ReadSecret(
		repoUUID, userUUID, userPwd, secretName)
	defer himitsu.Zero(secret)
	if err != nil {
		if _, ok := err.(*himitsu.ErrUnknownSecret); ok {
			rw.WriteHeader(http.StatusNotFound)
			rw.Write([]byte(err.Error()))
			return
		}
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		log.Print(err)
		return
	}

	if format == "raw" || format == "" {
		rw.WriteHeader(http.StatusOK)
		rw.Write(secret)
	} else if format == "base64" {
		s := base64.StdEncoding.
			EncodeToString(secret)
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(s))
	} else {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("unknow format"))
	}
}

func handleCreateSecret(rw http.ResponseWriter, req *http.Request) {
	repoUUID := req.URL.Query().Get("repo_uuid")
	userUUID := req.URL.Query().Get("user_uuid")
	userPwd := req.URL.Query().Get("user_pwd")
	secretName := req.URL.Query().Get("secret_name")
	secretValue := req.URL.Query().Get("secret_value")

	err := h.WriteSecret(repoUUID, userUUID, userPwd, secretName, []byte(secretValue))
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("OK"))
}
