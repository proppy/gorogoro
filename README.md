gorogoro
========

gorogoro helps lazy gophers to run their programs in the cloud.

## Installation

```
go get github.com/proppy/gorogoro
```

## Usage

```
gorogoro [github.com/import/path]
```

## Examples

```
$ gorogoro example/
2014/06/08 16:42:25 container port 8080/tcp available running at: 199.223.234.231:49156
```

```
$ gorogoro -port 4001 github.com/coreos/etcd
2014/06/08 16:42:19 container port 4001 available running at: 199.223.234.231:49155
```

```
$ cd some/go/pkg && gorogoro`
2014/06/08 17:00:53 container port 8080/tcp available running at: 199.223.234.231:49162
```

## How it works

gorogoro:
- reads gcloud credentials
- provision a virtual machine with a persistent disk w/ docker running
- compress the given go import path as a tar
- call docker build with `google/golang-runtime`
- call docker run
- create a firewall for the exposed port

## TODO

- attach stdout
- target tag firewall
