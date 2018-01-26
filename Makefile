DBVERSION := 3
ECSVERSION := 3
ROOT_NAME := aqfer
DBNAME := DB${ROOT_NAME}${DBVERSION}

AWS_ACCOUNT := 392630614516
JWT := testkey

AMI := ami-832b1cf9
# AMI := ami-fad25980 # ecs optimized ami
INSTANCE_TYPE := t2.medium
# INSTANCE_TYPE := c5.large
VPC := vpc-5a340c22
SUBNET := subnet-867f59cd
SUBNET2 := subnet-2cba2771
ZONE := us-east-1a
APP_LOG_GROUP_NAME := aqfer.io
KEYPAIR_NAME := AqferKeyPair

EC_SECURITY_GROUP := ${ROOT_NAME}EC-sg${DBVERSION}
EC_CLUSTER_NAME := elasticache${ROOT_NAME}${DBVERSION}
EC_NODE_TYPE := cache.m4.large
DAX_SECURITY_GROUP := ${ROOT_NAME}DAX-sg${DBVERSION}
DAX_CLUSTER_NAME := dax${ROOT_NAME}${DBVERSION}
DAX_NODE_TYPE := dax.r3.large
DYNAMO_TABLE := ${ROOT_NAME}-idsync${DBVERSION}
PARTITION_KEY := partition-key
SORT_KEY := sort-key

TASK_DEFINITION := ${ROOT_NAME}TaskDefinition${ECSVERSION}
ECS_LOG_GROUP_NAME := /ecs/${TASK_DEFINITION}
ECS_SERVICE := ${ROOT_NAME}Service${ECSVERSION}
EC2_SECURITY_GROUP := ${ROOT_NAME}EC2-sg${ECSVERSION}
LOAD_BALANCER_NAME := ${ROOT_NAME}LoadBalancer${ECSVERSION}
LB_SECURITY_GROUP := ${ROOT_NAME}LB-sg${ECSVERSION}


# bucket name must be all lowercase, and start/end with lowecase letter or number
ARTIFACTS_BUCKET := cloudformation-art-${ROOT_NAME}

.PHONY: dev
dev: aws_build

.PHONY: setup
setup: aws_build create_artifact_bucket create_keypair

.PHONY: aws_build
aws_build:
	docker build -f aqfer/Dockerfile.aws -t aws_image .

ID ?= $(shell docker-compose -f aqfer/docker-compose-aws.yml run \
	aws-service echo $$(aws configure get aws_access_key_id))
SECRET ?= $(shell docker-compose -f aqfer/docker-compose-aws.yml run \
	aws-service echo $$(aws configure get aws_secret_access_key))
REGION ?= $(shell docker-compose -f aqfer/docker-compose-aws.yml run \
	aws-service echo $$(aws configure get region))

.PHONY: create_artifact_bucket
create_artifact_bucket:
	docker-compose -f aqfer/docker-compose-aws.yml run \
		aws-service echo $$(aws s3 mb s3://${ARTIFACTS_BUCKET}/ --region ${REGION})


.PHONY: create_keypair
create_keypair:
	aqfer/scripts/keypair.sh ${KEYPAIR_NAME}

.PHONY: launch_db
launch_db:
	docker-compose -f aqfer/docker-compose-aws.yml run \
		aws-service aws cloudformation package --template-file aqfer/aws/db_template_app_spec.yml --output-template-file aqfer/aws/db_app_spec.yml --s3-bucket ${ARTIFACTS_BUCKET};\
		aws cloudformation deploy --template-file aqfer/aws/db_app_spec.yml --stack-name ${DBNAME} --capabilities \
		CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides \
		AWSAccount=${AWS_ACCOUNT} \
    AvailabilityZone=${ZONE} \
    Subnet=${SUBNET} \
    Vpc=${VPC} \
    DynamoTableName=${DYNAMO_TABLE} \
    PartitionKey=${PARTITION_KEY} \
    SortKey=${SORT_KEY} \
    DaxName=${DAX_CLUSTER_NAME} \
    DaxNodeType=${DAX_NODE_TYPE} \
    DaxRoleName=${ROOT_NAME}DaxRole${DBVERSION} \
    DaxSubnetGroupName=dax-subnet-${ROOT_NAME}${DBVERSION} \
    DaxSecurityGroupName=${DAX_SECURITY_GROUP} \
    ECSecurityGroupName=${EC_SECURITY_GROUP} \
    ECSubnetGroupName=elasticache-subnet-${ROOT_NAME}${DBVERSION} \
    ECNodeType=${EC_NODE_TYPE} \
    ECClusterName=${EC_CLUSTER_NAME}

.PHONY: delete_db
delete_db:
	docker-compose -f aqfer/docker-compose-aws.yml run \
		aws-service aws cloudformation delete-stack --stack-name ${DBNAME}


# .PHONY: launch_ecs
# launch_ecs:
		
