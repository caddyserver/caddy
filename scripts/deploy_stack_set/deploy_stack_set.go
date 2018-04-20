// deploy imds using cloud formation stack sets
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pborman/uuid"
	"github.com/aws/aws-sdk-go/aws/request"
	"time"
)

var svs *s3.S3
var svc *cloudformation.CloudFormation

func Check(e error, fn string) {
	if e != nil {
		panic(fmt.Sprintf("Function call failed : %s\n%v", fn, e))
	}
}

func WaitUntilStackSetOperationComplete(input *cloudformation.DescribeStackSetOperationInput) error {
	return WaitUntilStackSetOperationCompleteWithContext(aws.BackgroundContext(), input)
}

func WaitUntilStackSetOperationCompleteWithContext(ctx aws.Context, input *cloudformation.DescribeStackSetOperationInput, opts ...request.WaiterOption) error {
	w := request.Waiter{
		Name:        "WaitUntilStackSetOperationComplete",
		MaxAttempts: 120,
		Delay:       request.ConstantWaiterDelay(30 * time.Second),
		Acceptors: []request.WaiterAcceptor{
			{
				State:   request.SuccessWaiterState,
				Matcher: request.PathWaiterMatch, Argument: "Status",
				Expected: "SUCCEEDED",
			},
			{
				State:   request.FailureWaiterState,
				Matcher: request.PathWaiterMatch, Argument: "Status",
				Expected: "STOPPED",
			},
			{
				State:    request.FailureWaiterState,
				Matcher:  request.ErrorWaiterMatch,
				Expected: "ValidationError",
			},
		},
		Logger: svc.Config.Logger,
		NewRequest: func(opts []request.Option) (*request.Request, error) {
			var inCpy *cloudformation.DescribeStackSetOperationInput
			if input != nil {
				tmp := *input
				inCpy = &tmp
			}
			req, _ := svc.DescribeStackSetOperationRequest(inCpy)
			req.SetContext(ctx)
			req.ApplyOptions(opts...)
			return req, nil
		},
	}
	w.ApplyOptions(opts...)

	return w.WaitWithContext(ctx)
}

func main() {
	var stackSetName, s3ArtifactBucket, awsAccountId, awsRegion, deployRegions, stackParams string
	var templateBody, templateFile string = "", ""
	flag.StringVar(&awsAccountId, "account", "914664294701", "aws account id to deploy")
	flag.StringVar(&awsRegion, "region", "us-east-1", "aws regions to create stack set")
	flag.StringVar(&deployRegions, "deployregions", "", "comma separated list of regions to deploy")
	flag.StringVar(&s3ArtifactBucket, "s3bucket", "cloudformation-imds-art", "s3 bucketname where build packages are kept")
	flag.StringVar(&stackSetName, "stack", "", "cloudformation stack name (default $service-$stage)")
	flag.StringVar(&stackParams, "parameters", "", "comma seperated list of parameters to stack.(key:value,key:val...)")
	flag.StringVar(&templateFile, "template", "", "cloudformation template file path")
	flag.Parse()

	if stackSetName == "" || templateFile == "" || deployRegions == "" || s3ArtifactBucket == "" || stackParams == "" {
		fmt.Println("error: Required field(s) stack|template|deployregions|s3bucket|parameters")
		flag.PrintDefaults()
		os.Exit(2)
	}

	fmt.Println("# Create aws session, and connections to aws services")
	sess, err := session.NewSession(&aws.Config{Region: aws.String(awsRegion)})
	Check(err, "aws:NewSession()")
	svc = cloudformation.New(sess)
	svs = s3.New(sess)

	dat, err := ioutil.ReadFile(templateFile)
	Check(err, "Read local template for integ testing")
	templateBody = string(dat)

	var parameters []*cloudformation.Parameter

	stackSetOperationId := aws.String(fmt.Sprintf("op-%s", uuid.NewRandom().String()))
	fmt.Println("# Check for presence of existing stack set")
	dssOut, err := svc.DescribeStackSet(&cloudformation.DescribeStackSetInput{StackSetName: &stackSetName})
	if err == nil {
		fmt.Println("# Stack set exists. Updating...")
		parameters = dssOut.StackSet.Parameters
		if stackParams != "" {
			stackParamsArray := strings.Split(stackParams, ",")
			for _, s := range stackParamsArray {
				p := strings.Split(s, ":")
				k, v := p[0], p[1]
				for p := range parameters {
					if *parameters[p].ParameterKey == k {
						*parameters[p].ParameterValue = v
					}
				}
			}
		}
		result, err := svc.UpdateStackSet(&cloudformation.UpdateStackSetInput{
			StackSetName: &stackSetName,
			TemplateBody: &templateBody,
			Capabilities: []*string{aws.String("CAPABILITY_IAM"), aws.String("CAPABILITY_NAMED_IAM")},
			Parameters: parameters,
			OperationId: stackSetOperationId,
		})
		Check(err, "cloudformation.UpdateStackSet()")

		fmt.Println("# Waiting for stack set update to complete...")
		fmt.Printf("# OperationId for update: %v\n", *result.OperationId)
		err = WaitUntilStackSetOperationComplete(&cloudformation.DescribeStackSetOperationInput{OperationId: result.OperationId})
		if err != nil {
			fmt.Println("error: ", err)
			os.Exit(2)
		} else {
			Check(err, "cloudformation.WaitUntilStackSetOperationComplete")
		}
	} else {
		if strings.Contains(err.Error(), "not found") {
			if stackParams == "" {
				panic("When creating a new stack set, all parameters to template must be passed through -parameters option")
			}
			fmt.Println("# Stack set does not exist. Creating...")
			stackParamsArray := strings.Split(stackParams, ",")
			for _, s := range stackParamsArray {
				p := strings.Split(s, ":")
				k, v := p[0], p[1]
				parameters = append(parameters, &cloudformation.Parameter{ParameterKey: &k, ParameterValue: &v})
			}
			result, err := svc.CreateStackSet(&cloudformation.CreateStackSetInput{
				StackSetName: &stackSetName,
				TemplateBody: &templateBody,
				Capabilities: []*string{aws.String("CAPABILITY_IAM"), aws.String("CAPABILITY_NAMED_IAM")},
				Parameters: parameters,
			})
			Check(err, "cloudformation.CreateStackSet()")
			stackSetId := result.StackSetId
			fmt.Printf("# Stack set creation complete: %v\n", *stackSetId)
		} else {
			Check(err, "cloudformation:DescribeStacks()")
		}
	}

	fmt.Println("# Stack set deploy completed.")
}
