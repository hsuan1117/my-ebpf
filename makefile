# generate vmlinux header
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 

# build bpf kernel object file
minimal.bpf.o: minimal.bpf.c vmlinux.h
	clang -g -O2 -target bpf -c $< -o $@

# generate skeleton
minimal.skel.h: minimal.bpf.o
	bpftool gen skeleton $< > $@

# build app
minimal: minimal.c minimal.skel.h
	clang -g minimal.c -lbpf -lelf -lz -o $@

tcprtt.bpf.o: tcprtt.bpf.c vmlinux.h
	clang -g -O2 -target bpf -c $< -o $@

tcprtt.skel.h: tcprtt.bpf.o
	bpftool gen skeleton $< > $@

tcprtt: tcprtt.c tcprtt.skel.h
	clang -g tcprtt.c -lbpf -lelf -lz -o $@


tcprtt_tp.bpf.o: tcprtt_tp.bpf.c vmlinux.h
	clang -g -O2 -target bpf -c $< -o $@

tcprtt_tp.skel.h: tcprtt_tp.bpf.o
	bpftool gen skeleton $< > $@

t: tcprtt_tp.c tcprtt_tp.skel.h
	clang -g tcprtt_tp.c -lbpf -lelf -lz -o $@

clean:
	rm -f minimal minimal.bpf.o minimal.skel.h tcprtt tcprtt.bpf.o tcprtt.skel.h tcprtt_tp tcprtt_tp.bpf.o tcprtt_tp.skel.h