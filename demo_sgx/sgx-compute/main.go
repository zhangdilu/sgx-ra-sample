package main

import (
	"fmt"
	"github.com/sgx-ra/demo_sgx/sgx-compute/app"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

type digitalEnvelope struct{
}

func (m *digitalEnvelope) Init(stub shim.ChaincodeStubInterface) peer.Response{
	return shim.Success(nil)
}

func (m *digitalEnvelope) Invoke(stub shim.ChaincodeStubInterface) peer.Response{
	fn, args := stub.GetFunctionAndParameters()
	switch fn {
	case "compute":
		return app.ExecuteTask(stub, args)
	default:
		return shim.Error("invalid method")
	}
}
func main(){
	if err := shim.Start(new(digitalEnvelope)); err != nil{
		fmt.Printf("Error starting MetaData chaincode: %s", err)
	}
}
