# Evaluation of wasm-bpf

## Includes
- Compare startup delay of `example/bootstrap` among native, wasm-bpf, and docker
- Try run examples on bpftime
- Test map syscall speed (call per second) amond wasm-bpf, native
- Test ringbuf poll speed. Produce events on a uprobe hook, and test how many events can we handle per second
