####What is this?

Let's you create sign/ verify and run a self test on arbitary messages

##Generate public / private keys

openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem \n
openssl ec -in private_key.pem -pubout -out public_key.pem