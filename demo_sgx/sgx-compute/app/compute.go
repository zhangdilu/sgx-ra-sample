package app
// #cgo CFLAGS: -I${SRCDIR}/ -I/opt/intel/sgxsdk/include/
// #cgo LDFLAGS: ${SRCDIR}/libapp.a /opt/intel/sgxsdk/lib64/libsgx_urts.so /opt/openssl/1.1.0i/lib/libcrypto.so
// #include<./app.h>
import "C"
import (
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"strconv"
)

func ExecuteTask(stub shim.ChaincodeStubInterface, args []string)peer.Response{
	result := C.testDigitalEnvelope(1)
	return shim.Success([]byte(strconv.FormatInt(int64(result),10)))
}
