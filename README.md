## Initialize secrets repository
```
$ curl -i -k -X POST "https://localhost:8443/repositories?repo_label=foo&user_label=admin&user_pwd=<user-password>"
-> take 'repository uuid', 'user uuid'
```

## Define secret
```
$ curl -i -k -X POST "https://localhost:8443/secrets?repo_uuid=<repo_uuid>&user_uuid=<user_uuid>&user_pwd=<user_password>&secret_name=my_secret&secret_value=Hello World !"
```

## Read secret
```
$ curl -i -k "https://localhost:8443/secrets/<secret_name>?repo_uuid=<repo_uuid>&user_uuid=<user_uuid>&user_pwd=<user_password>&format=(raw|base64)"
```

## List secrets
```
$ curl -i -k "https://localhost:8443/secrets?repo_uuid=<repo_uuid>&user_uuid=<user_uuid>&user_pwd=<user_password>"
```

# Install (production)
```
$ go install ./...
$ $GOBIN/himitsu_server
```

# Run (dev/test)

```
$ go run himitsu_server/*.go
```

