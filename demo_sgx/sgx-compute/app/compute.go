package app
// #cgo LDFLAGS: -L${SRCDIR} -L /opt/sgxsdk/lib64 -llibapp -l sgx_urts -llibcrypto
// extern int testDigitalEnvelope(int symbol);
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
