server: go tool air --build.cmd "make build-server" --build.bin "./bin/airunner-server" -build.args_bin rpc-server,--development,--cert=./.certs/cert.pem,--key=./.certs/key.pem,--no-auth,--store-type=postgres,--postgres-auto-migrate
website: go tool air --build.cmd "make build-server" --build.bin "./bin/airunner-server" -build.args_bin website,--cert=./.certs/cert.pem,--key=./.certs/key.pem,--store-type=postgres
agent: go tool air --build.cmd "make build-cli" --build.bin "./bin/airunner-cli" -build.args_bin worker
