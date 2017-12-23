package main

import (
	"github.com/eawsy/aws-cloudformation-go-customres/service/cloudformation/customres"
)

var (
	// Handle is the Lambda's entrypoint.
	Handle customres.LambdaHandler
)

func init() {
	Handle = customres.HandleLambda
}

// Happy IDE means happy developer.
func main() {
}
