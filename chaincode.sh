//these steps run after generating enclave.signed.so
docker cp /home/mpc/go/src/github.com/sgx-ra/Enclave/Enclave.signed.so 83517eae918a:/usr/local/bin
docker cp /home/mpc/go/src/github.com/sgx-ra/demo_sgx/sealeddata.bin 83517eae918a:/usr/local/bin
