Simple PBFT
------

This repository contains the golang code of simple pbft consensus implementation.

  
How to run
------

## Build

```shell script
go build 
```

# Auto Execute
```
chmod -R 777 ./ 
./cmd.sh
```

<!-- ### Start four pbft node

```shell script
./optimizePBFT pbft node -id 0
./optimizePBFT pbft node -id 1
./optimizePBFT pbft node -id 2
./optimizePBFT pbft node -id 3
./optimizePBFT pbft node -id 4
./optimizePBFT pbft node -id 5
./optimizePBFT pbft node -id 6
./optimizePBFT pbft node -id 7
``` -->

### Start pbft client to send message
```
./optimizePBFT pbft client -id 8
```

<!-- ```shell script
./optimizePBFT pbft client  -id 8
./optimizePBFT pbft client  -id 9
./optimizePBFT pbft client  -id 10
./optimizePBFT pbft client  -id 11
./optimizePBFT pbft client  -id 12
./optimizePBFT pbft client  -id 13
./optimizePBFT pbft client  -id 14
./optimizePBFT pbft client  -id 15
``` -->

### Kill all process
```
ps -ef | grep ./optimizePBFT | grep -v grep | awk '{print$2}' | xargs kill -9
```
### Reference

- https://www.jianshu.com/p/78e2b3d3af62

```
panic: open go/src/github.com/optimizePBFT/Keys/9_priv: no such file or directory
```
delete the directory of "Keys", and run twice.