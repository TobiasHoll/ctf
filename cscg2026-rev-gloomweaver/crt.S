.pushsection .rela.dyn, "a"
	.ascii "(patch: fake relocation)"
	.ascii "(patch: fake relocation)"
	.ascii "(patch: fake relocation)"
.popsection

.pushsection .got, "aw"
    .ascii "(p: got)"
.popsection

.extern "crt0.o"
.weak "crt0.o"
.pushsection .data
	.quad "crt0.o"
.popsection

# We would want this to appear behind crtn.o.
# But that's annoying to do.
# So... emulate it ourselves.
.pushsection .fini
    addq $0x8, %rsp
    ret
.popsection
