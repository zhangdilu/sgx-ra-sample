package main
// #cgo CFLAGS: -I${SRCDIR}/ -I/opt/intel/sgxsdk/include/
// #cgo LDFLAGS: ${SRCDIR}/libapp.a /opt/intel/sgxsdk/lib64/libsgx_urts.so /opt/openssl/1.1.0i/lib/libcrypto.so
// #include<./app.h>
import "C"

func main() {
  C.testDigitalEnvelope(1)
}
