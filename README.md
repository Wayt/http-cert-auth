# HTTP Certificate client auth

This is a basic implementation of ssl client certificate authentication without certification authority (CA).

The purpose here is to behave like an SSH key authentication

We authorize self signed .crt on server side.

## Usage

First generate server certs, used for ssl transport

```sh
$ ./genssl.sh server
```

Then generate a client cert

```sh
$ mkdir authorizedkeys
$ ./genssl.sh authorizedkeys/client
```

Run the server

```sh
$ go run server.go -bind :4242 -key server.key -cert server.crt -clients ./authorizedkeys
2016/11/28 14:52:07 Loaded 1 certificate(s)
2016/11/28 14:52:07 listen :4242
```

Call using curl

```sh
curl -v --insecure --key authorizedkeys/client.key --cert authorizedkeys/client.crt \
    https://localhost:4242/hello
```

You can generate a new client cert outside `authorizedkeys` directory to try an unauthorized one.

## Disclaimer

On MacOS X, since Mavericks, ssl certs are managed by Apple keychain. See https://curl.haxx.se/mail/archive-2014-10/0053.html

## Credits

Most of this code was inspired by lxd works on the matter https://github.com/lxc/lxd
