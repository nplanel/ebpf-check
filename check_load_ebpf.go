// +build ebpf

/*
 * Copyright (C) 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy ofthe License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/skydive-project/skydive/common"
)

// #cgo CFLAGS: -I../../skydive-project/skydive/probe/ebpf
// #include "flow.h"
import "C"

const BPF_ANY = 0

func loadJumpMap(module *elf.Module) error {
	var jmpTable []string = []string{"socket_network_layer"}

	jmpTableMap := module.Map("jmp_map")
	if jmpTableMap == nil {
		return fmt.Errorf("Map: jmp_map not found")
	}
	for i, sym := range jmpTable {
		entry := module.SocketFilter(sym)
		if entry == nil {
			return fmt.Errorf("Symbol %s not found", sym)
		}

		index := uint32(i)
		fd := uint32(entry.Fd())
		err := module.UpdateElement(jmpTableMap, unsafe.Pointer(&index), unsafe.Pointer(&fd), BPF_ANY)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	ret := 0
	if len(os.Args) < 2 {
		fmt.Printf("usage : %s <flow.o>\n", os.Args[0])
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("can't open/read file : %s : %v\n", os.Args[1], err)
		os.Exit(1)
	}
	reader := bytes.NewReader(data)
	module := elf.NewModuleFromReader(reader)

	err = module.Load(nil)
	if err != nil {
		fmt.Printf("Unable to load eBPF elf binary (host %s) :\n%s\n", runtime.GOARCH, err)
		os.Exit(1)
	}

	if strings.Contains(os.Args[1], "gre") {
		if err = loadJumpMap(module); err != nil {
			fmt.Printf("Unable to load eBPF jump table (host %s) :\n%s\n", runtime.GOARCH, err)
			os.Exit(1)
		}
	}

	socketFilter := module.SocketFilter("socket_flow_table")
	if socketFilter == nil {
		panic("No flow_table socket filter")
	}

	var rs *common.RawSocket
	rs, err = common.NewRawSocket("any", common.AllPackets)
	if err != nil {
		panic(err)
	}
	fd := rs.GetFd()
	if err := elf.AttachSocketFilter(socketFilter, fd); err != nil {
		panic("Unable to attach socket filter to node: node-id-1234")
	}

	fmt.Println("listen traffic for 2sec ...")
	time.Sleep(2 * time.Second)

	nbFlows := 0
	fmap := module.Map("flow_table")
	if fmap == nil {
		panic("Unable to find flow_table map")
	}
	kernFlow := C.struct_flow{}
	var key, nextKey int64
	for {
		found, err := module.LookupNextElement(fmap, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&kernFlow))
		if !found || err != nil {
			break
		}
		key = nextKey
		// delete every entry after we read the entry value
		module.DeleteElement(fmap, unsafe.Pointer(&key))
		nbFlows++
	}

	if nbFlows == 0 {
		fmt.Println("no flow recieved")
		ret = 1
	} else {
		fmt.Printf("nbFlows %d\n", nbFlows)
	}

	if err := elf.DetachSocketFilter(socketFilter, fd); err != nil {
		panic("Unable to detach socket filter to node: node-id-1234")
	}
	rs.Close()

	err = module.Close()
	if err != nil {
		fmt.Println("module.Close() error ", err)
		os.Exit(1)
	}
	if ret == 0 {
		fmt.Println("PASS: load and test flow.o")
	}
	os.Exit(ret)
}
