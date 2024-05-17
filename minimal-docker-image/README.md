# statically linked bootstrap and docker image
```
cd bootstrap && make -j8
docker build .
docker run --privileged -it -v /sys:/sys XXXX
```
- Note this container can't be terminated with `Ctrl+C`. You have to use docker kill
