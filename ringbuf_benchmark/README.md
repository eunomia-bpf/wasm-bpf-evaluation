# How to run tests?

## native
```console
cd uprobe
make clean
make -f Makefile.native clean
make -f Makefile.native -j4
./uprobe
```

## wasm-bpf
```console
cd uprobe
make clean
make -j4
./target &
../../assets/wasm-bpf ./uprobe.wasm
```
## docker
```console
cd uprobe
make clean
make -f Makefile.native clean
make -f Makefile.native -j4
cd ..
docker build .
docker run --privileged -v /sys:/sys <DOCKER_IMAGE>
```
