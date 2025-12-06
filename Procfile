server: go tool air --build.cmd "make build-server" --build.bin "./bin/airunner-server" -build.args_bin rpc-server,--cert=./.certs/cert.pem,--key=./.certs/key.pem,--dev,--no-auth
agent: go tool air --build.cmd "make build-cli" --build.bin "./bin/airunner-cli" -build.args_bin worker
