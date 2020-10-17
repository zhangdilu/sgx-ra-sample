#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

main:
	cp app/*.so /chaincode/output
	cp app/*.a /chaincode/output
	cp app/sealeddata.bin /chaincode/output
	cp app/e_aes.bin /chaincode/output
	cp app/cipher.txt /chaincode/output

.PHONY: clean
clean:
	$(MAKE) -C sgx clean
	rm -rf enclave.signed.so libapp.a main go-sgx libapp.so go
