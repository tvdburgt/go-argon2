# go-argon2
Go bindings for Argon2

Installation is manual for now:

    go get -d github.com/tvdburgt/go-argon2
    cd $GOPATH/src/github.com/tvdburgt/go-argon2
    git submodule update --init # Might be unnecessary with GO15VENDOREXPERIMENT=1
    cd libargon2
    make && rm *.so

Documentation: https://godoc.org/github.com/tvdburgt/go-argon2
