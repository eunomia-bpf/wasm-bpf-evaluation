package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed lsm.bpf.o
var obj []byte

type Lsm struct {
	PathRmdir *ebpf.Program `ebpf:"path_rmdir"`
}

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		log.Fatal(err)
	}
	// ebpf.Assign
	obj := Lsm{}
	// spec.
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		log.Fatal(err)
	}
	defer obj.PathRmdir.Close()
	_, err = link.AttachLSM(link.LSMOptions{
		Program: obj.PathRmdir,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Attach ok")
	for {
		time.Sleep(10 * time.Second)
	}
}
