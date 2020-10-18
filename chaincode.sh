#these steps run after generating enclave.signed.so
docker cp /home/mpc/go/src/github.com/sgx-ra/Enclave/Enclave.signed.so 83517eae918a:/usr/local/bin
docker cp /home/mpc/go/src/github.com/sgx-ra/demo_sgx/sealeddata.bin 83517eae918a:/usr/local/bin
#to regenerate libapp.a
cp /home/mpc/go/src/github.com/sgx-ra/Enclave/Enclave.signed.so /home/mpc/go/src/github.com/sgx-ra/demo_sgx/sgx-compute/app
cp /home/mpc/go/src/github.com/sgx-ra/demo_sgx/sealeddata.bin /home/mpc/go/src/github.com/sgx-ra/demo_sgx/sgx-compute/app
