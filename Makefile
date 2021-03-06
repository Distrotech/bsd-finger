# You can do "make SUB=blah" to make only a few, or edit here, or both
# You can also run make directly in the subdirs you want.

SUB =   finger fingerd
INSTALLROOT = $(DESTDIR)

%.build:
	(cd $(patsubst %.build, %, $@) && $(MAKE))

%.install:
	(cd $(patsubst %.install, %, $@) && $(MAKE) INSTALLROOT=$(INSTALLROOT) install)

%.clean:
	(cd $(patsubst %.clean, %, $@) && $(MAKE) clean)

all:     $(patsubst %, %.build, $(SUB))
install: $(patsubst %, %.install, $(SUB))
clean:   $(patsubst %, %.clean, $(SUB))

distclean: clean
	rm -f MCONFIG
