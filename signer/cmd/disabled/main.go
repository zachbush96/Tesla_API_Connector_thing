package main

import (
	"fmt"
	r "example.invalid/tesla-connector/restricted"
)

func main() {
	fmt.Printf("{\"execution_enabled\":false,\"credentials_loaded\":false,\"listener_started\":false,\"sdk_commit\":%q}\n", r.SDKCommit)
}
