AR=lib
RM=del
CC=cl
CFLAGS=-c -I./inttypes $(CFLAGS)

OBJS = snprintf.obj \
       insnsa.obj \
       insnsb.obj \
       insnsd.obj \
       insnsn.obj \
       sync.obj \
       regs.obj \
       regdis.obj \
       nasmlib.obj \
       disasm.obj

all: disasm.lib

clean:
	$(RM) *.obj *.lib

disasm.lib: $(OBJS)
	$(AR) $(OBJS) /out:$@
