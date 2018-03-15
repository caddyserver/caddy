*Architecture Description*

**AWS Stack**

***Databases***
****EC Components****
- ElastiCache with redis and 1 node as defaults. AvailabilityZone, NodeType, ClusterName are params set in configuration.
- ElastiCache SecurityGroup has default generic description, SecurityGroupName and VPC are params set in configuration.
- ElastiCache SubnetGroup has default generic description, SubnetGroupName and Subnet are params set in configuration.

****Scripts****
- spin_up_db.sh script will run `aws cloudformation package` command. Written for docker container, leverages environment variables.
- Makefile target `spin_up_db` runs the script. ElastiCache params are meant to be configured in the Makefile.

***Caddy Service***
****ECS Components****
- ECSCluster takes ClusterName as param set in configuration.
- ECSTaskDefinition with 512cpu, 400mb memory, 1024000 file ulimit, 'awslogs' log driver, and portmappins at 80 and 8082 (ports used in Caddyfile) on containers as default. 
- ECSTaskDefinition has TaskDefinitionName, ContainerName, ECRRepoUri, log driver variables, AWS and JWT environment variables as params set in configuration.
- ECSService for ECSCluster using above ECSTaskDefinition; desired task count is 8, min health percent 100, max health percent 200, EC2 launch type, and containers at port 8082 by default.
-	ECSService uses 'spread' placement strategy across availability zones and instanceIds. Container to use is designated by ContainerName which is a param set in configuration.
- ECSServiceRole with EC2 SecurityGroupIngress authorization and describe policies, ElasticLoadBalancing deregister, register, and describe policies; takes RoleName as param set in configuration.
- NetworkLoadBalancer is set to network type, ipv4 address, and internet-facing scheme by default. LoadBalancerName and Subnets to use are set on params in configuration (2 subnets minimum required).
- LBListener connects ECSService to NetworkLoadBalancer and LBTargetGroup on TCP port 80 by default.
- LBTBTargetGroup will do health checks on ec2 instances on TCP port 80 by default. VPC and TargetGroupName are params set in configuration.

****EC2 Components****
- EC2InstanceProfile for EC2InstanceRole, Role has policies for S3 Get and List; create LogGroup and LogStream and PutLogs; cloudformation, codedeploy, ec2, ecs, ecr, iam role and profile.
- EC2SecurityGroup has default generic description, SecurityGroup ingress for TCP ports 0-65535 (to allow load balancer automatically assigned ports), 22 (for ssh), 80 and 8082 (for docker/caddy).
- EC2SecurityGroup GroupName and VPC are params set in configuration.
- LaunchConfiguration set up with EC2InstanceProfile and EC2SecurityGroup above; default BlockDeviceMapping with ebs volume type gp2 of size 22 and name '/dev/xvdcz'.
- LaunchConfiguration params set up in configuration are the AMI, IncanceType, and KeyPair to use.
- LaunchConfiguration Metadata executes Cloudformation::Init with commands that start awslogs, docker service, and ecs.
- LaunchConfiguration UserData executes ecs-init scripts, writes variables into conf files for ecs logs and awslogs, signals LaunchConfiguration setup is done.
- AutoScalingGroup has desired capacity of EC2 instances defaulted to 2, minsize of 0, maxsize of 2, cooldown at 300, and EC2 healthchecks. Subnet and LaunchConfiguration are params set in configuration.

****Logs****
- ApplicationLogGroup and the ECSLogGroup are created in the ECS templates as well, the names for the logs are params set in configuration (only ECSLogGroup is referred to in other places within this template).

****Scripts****
- spin_up_ec.sh script will run `aws cloudformation package` command. Written for docker container, leverages environment variables.
- Makefile target `spin_up_ecs` runs the script. ElasticContainerService params are meant to be configured in the Makefile.


**Docker Containers**

***ECS Container***
- Used to run service on AWS in docker containers, AWS credentials need to be setup in the docker-compose.yml and docker-compose-aws.yml files before running Makefile targets.
- FROM golang:1.9
- go gets all static libraries needed for caddy project
- builds Caddy executable

***AWS Container***
- Used to deploy service, AWS credentials need to be setup in the docker-compose.yml and docker-compose-aws.yml files before running Makefile targets.
- FROM ubuntu
- apt-get installs apt-utils, python3, and curl
- pip installs awscli
- curls ecs-cli executable

**Caddy**
***Caddyfile modules and parameters***
- Caddy standard module `redir` to a test file on port 80, only used for loadbalancer/targetgroup healthchecks
  - The service itself runs on port 8082, either of these ports can be changed but references to them have to be altered in the cloudformation templates
- The `secrets` module makes static values available throughout service on package-level SliceMap; the one param this module tokes is the designated file(path) to read secrets from
- The `AWSCloudwatch` module will catch any errors thrown down the filter chain and log them to AWS Cloudwatch, the params it takes are:
	- log level (debug, info, warning, error, fatal, panic)
	- aws LogGroup name (this group has to exist in the AWS account that goes with the AWS credentials in the setup scripts)
	- aws Stream name root (LogStreams created will have this string at the start followed by a timestamp and a -# of docker instance)
	- buffer size (log event chan buffer)
	- params have to be given in the order they're listed above from left to right
- Caddy standard module `reauth`, takes a block of params, `path /v1` denotes what url paths should be authenticated, `failure status code=401` denotes that a failure to authenticate will return a 401
	- `refresh url...` denotes that the backend being used is called refresh (an extension written specifically for this project) 
		- it uses a refresh token to get an access token and, along with the client's access token in the originating request header, it gets security context for the client
	  - dependencies: the standard lib `caddy-cache` which is used to cache the security context, and `caddy-secrets` which is used to access the SecretsMap where the refresh token is kept
		- the params it uses are `url` for the endpoint to auth against, `skipverify` whether to ignore TLS errors, `timeout` for auth request, `follow` whether to follow redirects, `cache_path` where to keep cached security context, `lock_timeout` for file lock
- The `transformrequest` module grabs request url and query params and applies business logic before passing converted data down filter chain (handler functions)
- The `redis` module provides an API that sends commands to a Redis instance. The param following module name `redis` is the `host:port` address to a Redis instance; one additional param can be set, there are two possible values:
	- `testing` - automatically fakes command execution on a golang map (this was added to facilitate Elasticache development outside of AWS VPC)
	- `fallback` - will first try to run the command on the designated Redis instance, if it fails it executes on the golang map
- The `transformresponse` module converts request data in the filter chain into a Caddy service json response (used to put together entity object with values queried from Redis)

***Updates***
- Caddyfile is the result of replacing ALL-CAPS variable names with service values on the Caddyfile_template file, so any changes have to be made to the template file, not the Caddyfile file itself
- After editing the template file, running `make update_tasks` will create an updated Caddyfile, make a new docker image, update the ecr repo with the image, and stop current ECS tasks
- The ECS Service will spin up new tasks with the updated docker instances and the Caddy updates will have been propagated fully throughout the cluster once the tasks are up and running

**Logging**

