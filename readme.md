####What is this?

Let's you create sign/ verify and run a self test on arbitary messages
```go run . -op sign -priv private_key.pem -message hello```

```go run . -op verify -pub public_key.pem -message hello -signature a13bb19dfc4d1461e7b567f876f84a7bf302c87867340fcc9d874d28175cef4f181dd1e0e2b4e6b0c10c2b55b886c80b0cd5f8071382d42dcbf9b4247723a8b7```


```go run . -op verify -pub public_key.pem -message hellon -signature a13bb19dfc4d1461e7b567f876f84a7bf302c87867340fcc9d874d28175cef4f181dd1e0e2b4e6b0c10c2b55b886c80b0cd5f8071382d42dcbf9b4247723a8b7```


##Generate public / private keys

```openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem```

```openssl ec -in private_key.pem -pubout -out public_key.pem```