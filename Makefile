DBVERSION := 2
ECSVERSION := 3
ROOT_NAME := aqfer
DBNAME := DB${ROOT_NAME}${DBVERSION}
ECSNAME := ECS${ROOT_NAME}${ECSVERSION}

AWS_ACCOUNT := 392630614516
JWT := testkey
REPO_ID := 2

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

.PHONY: create_artifact_bucket
create_artifact_bucket:
	docker-compose -f aqfer/docker-compose-aws.yml run \
		aws-service aws s3 mb s3://${ARTIFACTS_BUCKET}/ --region $$AWS_DEFAULT_REGION

.PHONY: keypair
keypair:
	docker-compose -f aqfer/docker-compose-aws.yml run \
	      aws-service /scripts/keypair.sh ${KEYPAIR_NAME} 2>&1 > keypair.pem

.PHONY: launch_db
launch_db:
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      aws cloudformation package --template-file aqfer/aws/db_template_app_spec.yml --output-template-file \
		  aqfer/aws/db_app_spec.yml --s3-bucket ${ARTIFACTS_BUCKET};\
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

.PHONY: ready_caddyfile
ready_caddyfile:
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      /scripts/dax_endpoint.sh ${DAX_CLUSTER_NAME} 2>&1 > /tmp/dax_endpoint
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      /scripts/ec_endpoint.sh ${EC_CLUSTER_NAME} 2>&1 > /tmp/ec_endpoint
	cat aqfer/Caddyfile_template | sed 's/APP_LOG_GROUP_NAME/'${APP_LOG_GROUP_NAME}'/g' > /tmp/Caddyfile
	perl -pi -e 's/DYNAMO_TABLE/'${DYNAMO_TABLE}'/g' /tmp/Caddyfile
	perl -pi -e 's/PARTITION_KEY/'${PARTITION_KEY}'/g' /tmp/Caddyfile
	perl -pi -e 's/SORT_KEY/'${SORT_KEY}'/g' /tmp/Caddyfile
	perl -pi -e 's/EC_ENDPOINT/'$(shell cat /tmp/ec_endpoint)'/g' /tmp/Caddyfile
	cat /tmp/Caddyfile | sed 's/DAX_ENDPOINT/'$(shell cat /tmp/dax_endpoint)'/g' > aqfer/Caddyfile

.PHONY: delete_db
delete_db:
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      aws cloudformation delete-stack --stack-name ${DBNAME} --region $$AWS_DEFAULT_REGION

.PHONY: ecr_repo_push
ecr_repo_push:
	# docker build -t ${ROOT_NAME}-caddy -f aqfer/Dockerfile .
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      /scripts/ecr_create.sh ${ROOT_NAME} ${REPO_ID} 2>&1 > /tmp/ecrUri
	$(eval ecrUri := $(shell cat /tmp/ecrUri))
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      /scripts/ecr_login.sh $$AWS_DEFAULT_REGION 2>&1 > /tmp/ecrLogin
	cat /tmp/ecrLogin | docker login -u AWS --password-stdin ${ecrUri}
	docker tag ${ROOT_NAME}-caddy:latest ${ecrUri}
	docker push ${ecrUri}

.PHONY: launch_ecs
launch_ecs:
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      aws cloudformation package --template-file aqfer/aws/ecs_template_app_spec.yml --output-template-file \
		  aqfer/aws/ecs_app_spec.yml --s3-bucket ${ARTIFACTS_BUCKET};\
	      aws cloudformation deploy --template-file aqfer/aws/ecs_app_spec.yml --stack-name ${ECSNAME} --capabilities \
		  CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides \
		  Id=$$AWS_ACCESS_KEY_ID \
		  Secret=$$AWS_SECRET_ACCESS_KEY \
		  Jwt=${JWT} \
		  AWSAccount=${AWS_ACCOUNT} \
		  Ami=${AMI} \
		  Subnet=${SUBNET} \
		  Subnet2=${SUBNET2} \
		  Vpc=${VPC} \
		  AvailabilityZone=${ZONE} \
		  KeyPair=${KEYPAIR_NAME} \
		  LoadBalancerName=${LOAD_BALANCER_NAME} \
		  LBSecurityGroupName=${LB_SECURITY_GROUP} \
		  TargetGroupName=${ROOT_NAME}TargetGroup${ECSVERSION} \
		  EC2InstanceType=${INSTANCE_TYPE} \
		  EC2SecurityGroupName=${EC2_SECURITY_GROUP} \
		  EC2InstanceRoleName=${ROOT_NAME}EC2InstanceRole${ECSVERSION} \
		  ECSClusterName=${ROOT_NAME}Cluster${ECSVERSION} \
		  ECSServiceRoleName=${ROOT_NAME}ECSServiceRole${ECSVERSION} \
		  ECSTaskDefinitionName=${TASK_DEFINITION} \
		  ECSServiceName=${ROOT_NAME}Service${ECSVERSION} \
		  ECRRepoURI=$(shell cat /tmp/ecrUri)) \
		  ContainerName=${ROOT_NAME-caddy} \
		  AppLogGroupName=${APP_LOG_GROUP_NAME} \
		  ECSLogGroupName=${ECS_LOG_GROUP_NAME};\
	    aws ec2 authorize-security-group-ingress --group-name ${EC_SECURITY_GROUP} --source-group ${EC2_SECURITY_GROUP} --port \
		  $(shell cat /tmp/ec_endpoint | sed -E "s/.*:([0-9]*)/\1/p") --protocol tcp;\
	    aws ec2 authorize-security-group-ingress --group-name ${DAX_SECURITY_GROUP} --source-group ${EC2_SECURITY_GROUP} --port \
		  $(shell cat /tmp/dax_endpoint | sed -E "s/.*([0-9]*)/\1/p") --protocol tcp;\

.PHONY: get_dns_name
get_dns_name:
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      aws elbv2 describe-load-balancers --names ${LOAD_BALANCER_NAME} 2>&1 > /tmp/DNSName
	@echo $(shell cat /tmp/DNSName | sed -n -E "s/.*\"DNSName\".*\"(.*)\",/\1/p")

.PHONY: delete_ecs
delete_ecs:
	# need to add if statement here to check for passed in instances var
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      aws ec2 revoke-security-group-ingress --group-name ${EC_SECURITY_GROUP} --source-group ${EC2_SECURITY_GROP} --port \
		  $(shell cat /tmp/ec_endpoint | sed -E "s/.*:([0-9]*)/\1/p") --protocol tcp;\
	      aws ec2 revoke-security-group-ingress --group-name ${DAX_SECURITY_GROUP} --source-group ${EC2_SECURITY_GROP} --port \
		  $(shell cat /tmp/dax_endpoint | sed -E "s/.*:([0-9]*)/\1/p") --protocol tcp;\
	      aws ec2 terminate-instances --instance-ids $(instances);\
	      aws ec2 wait instance-terminated --instance-ids $(instances);\
	      aws cloudformation delete-stack --stack-name ${ECNAME}


