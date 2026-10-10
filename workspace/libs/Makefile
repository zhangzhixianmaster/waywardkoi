# Top-level Makefile for all authentication channel libraries
.PHONY: all clean install sms email totp cert

all: sms email totp cert

sms:
	$(MAKE) -C sms

email:
	$(MAKE) -C email

totp:
	$(MAKE) -C totp

cert:
	$(MAKE) -C cert

clean:
	$(MAKE) -C sms clean
	$(MAKE) -C email clean
	$(MAKE) -C totp clean
	$(MAKE) -C cert clean

install:
	$(MAKE) -C sms install
	$(MAKE) -C email install
	$(MAKE) -C totp install
	$(MAKE) -C cert install
	@echo ""
	@echo "All libraries installed to /usr/local/lib/"
	@echo "Ensure /usr/local/lib is in LD_LIBRARY_PATH or configure ldconfig"
