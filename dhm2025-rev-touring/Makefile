all: touring

codegen:
	@make -C gen assembler

raw: codegen
	gen/assembler text.iou rodata.iou

assembly: raw
	gen/postprocessing.py text.iou rodata.iou touring/generated.inc.c touring/generated.s

touring: assembly
	@make -C touring

test: touring
	grep -o 'DHM{[^}]*}' gen/assembler.cc | ./touring/touring

dist: assembly
	cd touring && docker build -f Dockerfile.build -t touring-builder .
	docker run --rm touring-builder > touring/touring
	chmod 755 touring/touring
	docker rmi touring-builder

.PHONY: codegen raw assembly touring test dist
