TOPLEVEL_GOPATH ?= $(GOPATH)
GOVENDOR:=$(TOPLEVEL_GOPATH)/bin/govendor
SKYDIVE_PATH:=$(TOPLEVEL_GOPATH)/src/github.com/skydive-project/skydive

all: check

build-check:
	export SKYDIVE_PATH
	#$(MAKE) -C $(SKYDIVE_PATH) govendor genlocalfiles
	$(GOVENDOR) build -x -v -tags ebpf check_load_ebpf.go

check: build-check
	$(MAKE) -C $(SKYDIVE_PATH) WITH_EBPF=true ebpf.build
	sudo ./check_load_ebpf $(SKYDIVE_PATH)/probe/ebpf/flow.o
	sudo ./check_load_ebpf $(SKYDIVE_PATH)/probe/ebpf/flow-gre.o

clean:
	rm -f check_load_ebpf
