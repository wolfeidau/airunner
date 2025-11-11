# airunner

This is demonstrating the use of [console-stream](https://github.com/wolfeidau/console-stream) and a [connectrpc](https://connectrpc.com/) server which recieves job events, and an agent which dequeues jobs and executes them.

# Prequisites

- Go 1.25.0 or later
- make
- [mkcert](https://github.com/FiloSottile/mkcert)
- [goreman](https://github.com/mattn/goreman) or [Foreman](https://github.com/ddollar/foreman)

# Usage

Before we start you need some certs, run `make certs` to generate them. Note you will want to setup mkcert on your system to generate the certificates.

```sh
brew install mkcert
make certs
```

In a shell window run.

```sh
goreman start
```

Then open another tab and run.

```sh
go run ./cmd/cli submit --config configs/example-job.yaml "https://github.com/wolfeidau/airunner"
```

This will enqueue a job to the airunner server, then monitor the job status and output the logs and the exit status.

You can see a history of jobs by running.

```sh
go run ./cmd/cli list
```

## License

Apache License, Version 2.0 - Copyright [Mark Wolfe](https://www.wolfe.id.au)
