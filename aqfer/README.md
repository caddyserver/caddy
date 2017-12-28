**Steps for project start-up:**
- Build Caddy binary docker image `docker build ./ -t aqfer-caddy`
- To run container locally execute `./start.sh`

**Steps for aws stack deployment:**
1. pip install --upgrade pip
2. pip install --upgrade awscli
3. configure values for stack on aws/createResources.sh
4. execute `./createResources.sh` in the aws directory
