# See LICENSE for license information
SGXSDK=/opt/intel/sgxsdk
SGXSDK_BINDIR=/opt/intel/sgxsdk/bin/x64
SGXSDK_INCDIR=/opt/intel/sgxsdk/include
SGXSDK_LIBDIR=/opt/intel/sgxsdk/lib64
SGX_URTS_LIB=sgx_urts
SGX_UAE_SERVICE_LIB=sgx_uae_service
SGX_EDGER8R=$(SGXSDK_BINDIR)/sgx_edger8r

ifndef SGX_ENCLAVE_SRCDIR
	SGX_ENCLAVE_SRCDIR=.
endif

.PHONY: inc_dummy

inc_dummy:
	@echo "Either specify a target, or move your default"
	@echo "target above the \"include\" line in your Makefile"

.PHONY: enclave_subdirs $(SGX_ENCLAVES)

enclave_subdirs: $(SGX_ENCLAVES)

$(SGX_ENCLAVES):
	$(MAKE) -C $@ $@.signed.so

distclean_enclaves:
	for dir in $(SGX_ENCLAVES); do \
		$(MAKE) -C $$dir distclean; \
	done

clean_enclaves:
	for dir in $(SGX_ENCLAVES); do \
		$(MAKE) -C $$dir clean; \
	done

define ENCLAVEU_template =
ENCLAVE_UOBJS += $(2)_u.o
ENCLAVE_CLEAN += $(2)_u.o $(2)_u.c $(2)_u.h
ENCLAVE_UDEPS += $(2)_u.c $(2)_u.h

$(2)_u.h $(2)_u.c: $(3)/$(1)/$(2).edl 
	$$(SGX_EDGER8R) $$(SGX_EDGER8R_FLAGS) --untrusted $$<

$(2)_u.o: $(2)_u.c $(2)_u.h
endef

$(foreach enclave, $(SGX_ENCLAVES),$(eval $(call ENCLAVEU_template,$(enclave),$(notdir $(enclave)),$(SGX_ENCLAVE_SRCDIR))))

