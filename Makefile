DBVERSION := 2
ECSVERSION := 4
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
EC_SUBNET_GROUP := elasticache-subnet-${ROOT_NAME}${DBVERSION}
DAX_SECURITY_GROUP := ${ROOT_NAME}DAX-sg${DBVERSION}
DAX_CLUSTER_NAME := dax${ROOT_NAME}${DBVERSION}
DAX_NODE_TYPE := dax.r3.large
DYNAMO_TABLE := ${ROOT_NAME}-idsync${DBVERSION}
PARTITION_KEY := partition-key
SORT_KEY := sort-key

ECS_CLUSTER_NAME := ${ROOT_NAME}Cluster${ECSVERSION}
TASK_DEFINITION := ${ROOT_NAME}TaskDefinition${ECSVERSION}
ECS_LOG_GROUP_NAME := /ecs/${TASK_DEFINITION}
ECS_SERVICE := ${ROOT_NAME}Service${ECSVERSION}
EC2_SECURITY_GROUP := ${ROOT_NAME}EC2-sg${ECSVERSION}
LOAD_BALANCER_NAME := ${ROOT_NAME}LoadBalancer${ECSVERSION}
LB_SECURITY_GROUP := ${ROOT_NAME}LB-sg${ECSVERSION}


# bucket name must be all lowercase, and start/end with lowecase letter or number
ARTIFACTS_BUCKET := cloudformation-art-${ROOT_NAME}

.PHONY: setup_and_launch
setup_and_launch: setup update_container_repo spin_up_stacks

.PHONY: full_launch
full_launch: update_container_repo spin_up_stacks


.PHONY: setup
setup: aws_build create_artifact_bucket create_keypair

.PHONY: update_container_repo
update_container_repo: ready_caddyfile ecr_repo_push

.PHONY: spin_up_stacks
spin_up_stacks: spin_up_db spin_up_ecs get_dns_name

.PHONY: update_tasks
update_tasks: update_container_repo stop_tasks

.PHONY: tear_down_stacks
tear_down_stacks: tear_down_db tear_down_ecs




.PHONY: aws_build
aws_build:
	docker build -f aqfer/Dockerfile.aws -t aws_image .

.PHONY: create_artifact_bucket
create_artifact_bucket:
	docker-compose -f aqfer/docker-compose-aws.yml run \
		aws-service aws s3 mb s3://${ARTIFACTS_BUCKET}/

.PHONY: keypair
keypair:
	docker-compose -f aqfer/docker-compose-aws.yml run \
	aws-service /scripts/keypair.sh ${KEYPAIR_NAME} 2>&1 > keypair.pem



.PHONY: spin_up_db
spin_up_db:
	docker-compose -f aqfer/docker-compose-aws.yml run \
	-e AWSAccount=${AWS_ACCOUNT} \
	-e AvailabilityZone=${ZONE} \
	-e Subnet=${SUBNET} \
	-e Vpc=${VPC} \
	-e DynamoTableName=${DYNAMO_TABLE} \
	-e PartitionKey=${PARTITION_KEY} \
	-e SortKey=${SORT_KEY} \
	-e DaxName=${DAX_CLUSTER_NAME} \
	-e DaxNodeType=${DAX_NODE_TYPE} \
	-e DaxRoleName=${ROOT_NAME}DaxRole${DBVERSION} \
	-e DaxSubnetGroupName=dax-subnet-${ROOT_NAME}${DBVERSION} \
	-e DaxSecurityGroupName=${DAX_SECURITY_GROUP} \
	-e ECSecurityGroupName=${EC_SECURITY_GROUP} \
	-e ECSubnetGroupName=${EC_SUBNET_GROUP} \
	-e ECNodeType=${EC_NODE_TYPE} \
	-e ECClusterName=${EC_CLUSTER_NAME} \
	aws-service /scripts/spin_up_db.sh ${ARTIFACTS_BUCKET} ${DBNAME}

# still need to test this one more time, if this works get rid of delete_db.sh
.PHONY: tear_down_db
tear_down_db:
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service aws cloudformation delete-stack --stack-name ${DBNAME}



.PHONY: get_db_endpoints
get_db_endpoints:
	# docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	#       /scripts/dax_endpoint.sh ${DAX_CLUSTER_NAME} 2>&1 > /tmp/dax_endpoint
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      /scripts/ec_endpoint.sh ${EC_CLUSTER_NAME} 2>&1 > /tmp/ec_endpoint

.PHONY: ready_caddyfile
ready_caddyfile: get_db_endpoints
	cat aqfer/Caddyfile_template | sed 's/APP_LOG_GROUP_NAME/'${APP_LOG_GROUP_NAME}'/g' > /tmp/Caddyfile
	perl -pi -e 's/DYNAMO_TABLE/'${DYNAMO_TABLE}'/g' /tmp/Caddyfile
	perl -pi -e 's/PARTITION_KEY/'${PARTITION_KEY}'/g' /tmp/Caddyfile
	perl -pi -e 's/SORT_KEY/'${SORT_KEY}'/g' /tmp/Caddyfile
	cat /tmp/Caddyfile | sed 's/EC_ENDPOINT/'$(shell cat /tmp/ec_endpoint)'/g' > aqfer/Caddyfile
	# perl -pi -e 's/EC_ENDPOINT/'$(shell cat /tmp/ec_endpoint)'/g' /tmp/Caddyfile
	# cat /tmp/Caddyfile | sed 's/DAX_ENDPOINT/'$(shell cat /tmp/dax_endpoint)'/g' > aqfer/Caddyfile

# do I need to build the main docker container here? test by launching a db with a different version number and see if the container pushed has the right address
.PHONY: ecr_repo_push
ecr_repo_push: build_caddy_image
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service /scripts/ecr_create.sh ${ROOT_NAME} ${REPO_ID} 2>&1 > /tmp/ecrUri
	$(eval ecrUri := $(shell cat /tmp/ecrUri))
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service /scripts/ecr_login.sh 2>&1 > /tmp/ecrLogin
	cat /tmp/ecrLogin | docker login -u AWS --password-stdin ${ecrUri}
	docker tag ${ROOT_NAME}-caddy:latest ${ecrUri}
	docker push ${ecrUri}

.PHONY: build_caddy_image
build_caddy_image:
	docker build -f aqfer/Dockerfile -t ${ROOT_NAME}-caddy .


.PHONY: spin_up_ecs
spin_up_ecs:
	docker-compose -f aqfer/docker-compose-aws.yml run \
	-e Jwt=${JWT} \
	-e AWSAccount=${AWS_ACCOUNT} \
	-e Ami=${AMI} \
	-e Subnet=${SUBNET} \
	-e Subnet2=${SUBNET2} \
	-e Vpc=${VPC} \
	-e AvailabilityZone=${ZONE} \
	-e KeyPair=${KEYPAIR_NAME} \
	-e LoadBalancerName=${LOAD_BALANCER_NAME} \
	-e LBSecurityGroupName=${LB_SECURITY_GROUP} \
	-e TargetGroupName=${ROOT_NAME}TargetGroup${ECSVERSION} \
	-e EC2InstanceType=${INSTANCE_TYPE} \
	-e EC2SecurityGroupName=${EC2_SECURITY_GROUP} \
	-e EC2InstanceRoleName=${ROOT_NAME}EC2InstanceRole${ECSVERSION} \
	-e ECSClusterName=${ECS_CLUSTER_NAME} \
	-e ECSServiceRoleName=${ROOT_NAME}ECSServiceRole${ECSVERSION} \
	-e ECSTaskDefinitionName=${TASK_DEFINITION} \
	-e ECSServiceName=${ROOT_NAME}Service${ECSVERSION} \
	-e ECRRepoURI=${ecrUri} \
	-e ContainerName=${ROOT_NAME}-caddy \
	-e AppLogGroupName=${APP_LOG_GROUP_NAME} \
	-e ECSLogGroupName=${ECS_LOG_GROUP_NAME} \
	aws-service /scripts/spin_up_ecs.sh ${ARTIFACTS_BUCKET} ${ECSNAME} \
	${EC_SECURITY_GROUP} $(shell cat /tmp/ec_endpoint | sed -E "s/.*:([0-9]*).*/\1/") \
	${DAX_SECURITY_GROUP} $(shell cat /tmp/dax_endpoint | sed -E "s/.*:([0-9]*).*/\1/")

.PHONY: tear_down_ecs
tear_down_ecs: get_db_endpoints
ifdef instances
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	     aws ec2 revoke-security-group-ingress --group-name ${EC_SECURITY_GROUP} --source-group ${EC2_SECURITY_GROUP} --port \
			 	$(shell cat /tmp/ec_endpoint | sed -E "s/.*:([0-9]*)/\1/") --protocol tcp;\
	     aws ec2 revoke-security-group-ingress --group-name ${DAX_SECURITY_GROUP} --source-group ${EC2_SECURITY_GROUP} --port \
			 	$(shell cat /tmp/dax_endpoint | sed -E "s/.*:([0-9]*)/\1/") --protocol tcp;\
	     aws ec2 terminate-instances --instance-ids $(instances);\
	     aws ec2 wait instance-terminated --instance-ids $(instances);\
	     aws cloudformation delete-stack --stack-name ${ECSNAME}
endif



.PHONY: get_dns_name
get_dns_name:
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service \
	      aws elbv2 describe-load-balancers --names ${LOAD_BALANCER_NAME} 2>&1 > /tmp/DNSName
	@echo $(shell cat /tmp/DNSName | sed -n -E "s/.*\"DNSName\".*\"(.*)\",/\1/p")

.PHONY: run_locally
run_locally:
	docker-compose -f aqfer/docker-compose.yml up

.PHONY: launch_locally
launch_locally: build_caddy_image run_locally
	docker-compose -f aqfer/docker-compose.yml up

.PHONY: stop_tasks
stop_tasks:
	docker-compose -f aqfer/docker-compose-aws.yml run aws-service /scripts/stop_tasks.sh ${ECS_CLUSTER_NAME}



.PHONY: run_unit_tests
run_unit_tests:
	docker-compose -f aqfer/docker-compose.yml run caddy /run_unit_tests.sh

.PHONY: run_integration_tests
run_integration_tests:
	docker-compose -f aqfer/docker-compose.yml run caddy /run_integration_tests.sh

