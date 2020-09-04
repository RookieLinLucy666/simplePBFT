Simple PBFT
------

This repository contains the golang code of simple pbft consensus implementation.

  
How to run
------

## Build

```shell script
go build 
```

### Start four pbft node

```shell script
./optimizePBFT pbft node -id 0
./optimizePBFT pbft node -id 1
./optimizePBFT pbft node -id 2
./optimizePBFT pbft node -id 3
```

### Start pbft client to send message

```shell script
./optimizePBFT pbft client
```


### Reference

- https://www.jianshu.com/p/78e2b3d3af62
