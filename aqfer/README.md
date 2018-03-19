# Architecture Description

## AWS Stack

### Databases
#### EC Components
- ElastiCache with static values of **1** node **redis** engine. *AvailabilityZone*, *NodeType*, *ClusterName* are configurable values.
- ElastiCache SecurityGroup has generic description. *SecurityGroupName* and *VPC* are configurable values.
- ElastiCache SubnetGroup has generic description. *SubnetGroupName* and *Subnet* are configurable values.

#### Scripts
- *spin_up_db.sh* script will run `aws cloudformation package` command. It's written to be executed inside a docker container leveraging environment variables set in script.
- Makefile target **spin_up_db** runs the script. ElastiCache values are meant to be configured in the Makefile.

### Caddy Service

#### ECS Components
- ECSCluster ClusterName is a configurable param.
- ECSTaskDefinition with static values of **512** cpu, **400mb** memory, **1024000** file ulimit, **awslogs** log driver, and portmappings to containers on **80** and **8082**. 
- *TaskDefinitionName*, *ContainerName*, *ECRRepoUri*, log driver variables, *AWS* and *JWT* environment variables are configurable values.
- ECSService for the ECSCluster using above ECSTaskDefinition; static values of **8** desired task count, **100** min health percent, **200** max health percent, **EC2** launch type, and loadbalancer dynamically mapped to containers on port **8082**.
- ECSService uses 'spread' placement strategy across availability zones and instance ids. Container to use is designated by 'ContainerName' which is a configurable param.
- ECSServiceRole with policies for EC2 SecurityGroupIngress authorization and describe actions, policies for ElasticLoadBalancing deregister, register, and describe actions; RoleName is a configurable param.
- NetworkLoadBalancer has static values of **network** for the type, **ipv4** for address type, and **internet-facing** scheme. *LoadBalancerName* and *Subnets* are configurable values (2 subnets minimum required).
- LBListener connects ECSService to NetworkLoadBalancer and LBTargetGroup on TCP port 80 (static values on ecs template).
- LBTBTargetGroup will do health checks on ec2 instances on TCP port 80 (static values on ecs template). *VPC* and *TargetGroupName* are configurable values.

#### EC2 Components
- EC2InstanceProfile for EC2InstanceRole, Role has policies for S3 Get and List; create LogGroup and LogStream and PutLogs; cloudformation, codedeploy, ec2, ecs, ecr, iam role and profile.
- EC2SecurityGroup has default generic description, SecurityGroup ingress for TCP ports 0-65535 (to allow load balancer automatically assigned ports), 22 (for ssh), 80 and 8082 (for docker/caddy).
- EC2SecurityGroup *GroupName* and *VPC* are configurable values.
- LaunchConfiguration set up with EC2InstanceProfile and EC2SecurityGroup above; BlockDeviceMapping has static values with ebs volume type **gp2** of size **22** and name */dev/xvdcz*. *AMI*, *IncanceType*, and *KeyPair* are configurable values.
- LaunchConfiguration Metadata executes Cloudformation::Init with commands that start awslogs, docker service, and ecs.
- LaunchConfiguration UserData executes ecs-init scripts, writes variables into conf files for ecs logs and awslogs, signals LaunchConfiguration setup is done.
- AutoScalingGroup has EC2 instances static values of **2** for desired capacity, **0** minsize, **2** maxsize, **300** cooldown, and **EC2** healthchecks. *Subnet* is a configurable value.

#### Logs
- The ApplicationLogGroup and the ECSLogGroup are created in the ECS cloudformation stack template as well, the names for the logs are configurable values. Only ECSLogGroup is referred to in other places within this template.

#### Scripts
- *spin_up_ec.sh* script will run `aws cloudformation package` command. It's written to be executed inside a docker container leveraging environment variables set in script.
- Makefile target **spin_up_ecs** runs the script. ElasticContainerService values are meant to be configured in the Makefile.

### Deploying Cloudformation Stacks
Configuration and deployment should be done from the Makefile by setting params and running targets. There are static values that can be modified in each of the ec and ecs templates or be made configurable by adding var references on the Makefile targets and bash scripts.

## Docker Containers

### ECS Container
- Used to run service on AWS in docker containers, AWS credentials need to be setup in the *docker-compose.yml* and *docker-compose-aws.yml* files before running Makefile targets.
- `FROM golang:1.9`
- static libraries needed for caddy project pulled with `go get`
- Caddy executable is built for docker `CMD`

### AWS Container
- Used to deploy service, AWS credentials need to be setup in the *docker-compose.yml* and *docker-compose-aws.yml* files before running Makefile targets.
- `FROM ubuntu`
- apt-utils, python3, and curl installed with `apt-get`
- awscli installed with `pip` to run cloudformation scripts

## Caddy

### Caddyfile modules and parameters
- Caddy standard module **redir** to points to a test file on port 80, only used for loadbalancer/targetgroup healthchecks
  - The service itself runs on port 8082, either of these ports can be changed but references to them have to be altered in the cloudformation templates
- The **secrets** module makes static values available throughout service on package-level SliceMap; the one param this module tokes is the designated file(path) to read secrets from
- The **awscloudwatch** module will catch any errors thrown down the filter chain and log them to AWS Cloudwatch, the params it takes are:
	- log level (debug, info, warning, error, fatal, panic)
	- aws LogGroup name (this group has to exist in the AWS account that goes with the AWS credentials in the setup scripts)
	- aws Stream name root (LogStreams created will have this string at the start followed by a timestamp and a -# of docker instance)
	- buffer size (log event chan buffer)
	- params have to be given in the order they're listed above from left to right
- Caddy standard module **reauth**, takes a block of params, `path /v1` denotes what url paths should be authenticated, `failure status code=401` denotes that a failure to authenticate will return a 401
	- `refresh url...` denotes that the backend being used is called refresh (an extension written specifically for this project) 
		- it uses a refresh token to get an access token and, along with the client's access token in the originating request header, it gets security context for the client
	  - dependencies: the standard lib **caddy-cache** which is used to cache the security context, and **caddy-secrets** which is used to access the SecretsMap where the refresh token is kept
		- the params it uses are **url** for the endpoint to auth against, **skipverify** whether to ignore TLS errors, **timeout** for auth request, **follow** whether to follow redirects, **cache_path** where to keep cached security context, **lock_timeout** for file lock
- The **transformrequest** module grabs request url and query params and applies business logic before passing converted data down filter chain (handler functions)
- The **redis** module provides an API that sends commands to a Redis instance. The param following module name *redis* is the address (host:port) to a Redis instance; one additional param can be set, there are two possible values:
	- *testing* - automatically fakes command execution on a golang map (this was added to facilitate Elasticache development outside of AWS VPC)
	- *fallback* - will first try to run the command on the designated Redis instance, if it fails it executes on the golang map
- The **transformresponse** module converts request data in the filter chain into a Caddy service json response (used to put together entity object with values queried from Redis)

### Updates
- Caddyfile is the result of replacing ALL-CAPS variable names with service values on the Caddyfile_template file, so any changes have to be made to the template file, not the Caddyfile file itself
- After editing the template file, running `make update_tasks` will create an updated Caddyfile, make a new docker image, update the ecr repo with the image, and stop current ECS tasks
- The ECS Service will spin up new tasks with the updated docker instances and the Caddy updates will have been propagated fully throughout the cluster once the tasks are up and running

## Monitoring

### Logs
Currently everything is in AWSCloudWatchLogs
- **Filterchain errors handled in-service**: each ECSTask has own stream (stream name configured in Caddyfile), log group name configured in Makefile (APP_LOG_GROUP_NAME)
- **Docker stdout**: each ECSTask has own stream (stream name is the task id), log group name configured in Makefile (ECS_LOG_GROUP_NAME)
- **ECS logs**: each EC2Instance in the cluster has a stream (stream name is instance id), log group name configured in ECS template (LaunchConfiguration UserData)
- **ECS agent logs**: each EC2Instance in the cluster has a stream (stream name is 'cluster name'/'instance id'), log group name configured in ECS template (LaunchConfiguration UserData)

### Metrics
- **ECSCluster**: MemoryReservation, CPUReservation, MemoryUtilization, CPUUtilization (Utilization can be separated by ECSService)
  - CloudWatch Alarms on these metrics would tell us when tasks are failing to be updated due to cpu or mem limitations
- **LoadBalancer/TargetGroup**: UnhealthyHostCount, HealthyHostCount (can be separated by AvailabilityZone)
  - CloudWatch Alarms on these metrics would tell us when Caddy is failing to get up and running
- **Elasticache**: [Redis Metrics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CacheMetrics.Redis.html)
  - CloudWatch Alarms on some of these metrics could explain lag or other runtime issues of the service
- **LogGroup**: Incoming LogEvents (this might not be as useful, since logs are currently batched in every 5 secs)
