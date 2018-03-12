package integration

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
)

var pwd string
var docker *exec.Cmd

func init() {
	exec.Command("/bin/sh", "-c", "cp ../Dockerfile.integration ./Dockerfile.integration").Run()
	exec.Command("/bin/sh", "-c", "cp ../test.yml ./test.yml").Run()
}

func RunDocker() {
	cmd := exec.Command("/bin/sh", "-c", "docker build -f Dockerfile.integration -t aqfer-integration .")
	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		fmt.Println(err.Error() + " : " + stderr.String())
	} else {
		fmt.Println(out.String())
	}

	// docker = exec.Command("/bin/sh", "-c", "docker-compose -f ../docker-compose-integration.yml up")
	docker = exec.Command("/bin/sh", "-c", "docker run -p 8082:8082 aqfer-integration")
	docker.Stdout = &out
	docker.Stderr = &stderr

	go func() {
		err := docker.Run()
		if err != nil {
			fmt.Println(err.Error() + " : " + stderr.String())
		}

		fmt.Println("Docker container was stopped")
		fmt.Println(out.String())
	}()
}

func GetTokenWithRefresh(token string) string {
	cmd := exec.Command("/bin/sh", "-c", "curl -X POST \"https://n0pwyybuji.execute-api.us-west-2.amazonaws.com/pre_prod/aqfer/auth/v1/access_token\" -d \"grant_type=refresh_token&refresh_token="+token+"\" -H \"Content-Type : application/x-www-form-urlencoded\" | python -m json.tool")
	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		fmt.Println(err.Error() + " : " + stderr.String())
		return ""
	}

	containerExp := regexp.MustCompile(".*\"jwt_token\": \"([A-Za-z0-9\\.\\-_]+)\",")
	match := containerExp.FindStringSubmatch(out.String())
	if len(match) == 0 {
		fmt.Println("no match:")
		fmt.Println(out.String())
	}
	return match[1]
}

func Cleanup() {
	fmt.Println("-----Cleaning up-----")

	container := exec.Command("/bin/sh", "-c", "docker ps")
	var out bytes.Buffer
	container.Stdout = &out
	var stderr bytes.Buffer
	container.Stderr = &stderr

	err := container.Run()
	if err != nil {
		fmt.Println(err.Error() + " : " + stderr.String())

	} else {
		containerExp := regexp.MustCompile("([0-9a-zA-Z]+)\\s*aqfer-integration.*")
		match := containerExp.FindStringSubmatch(out.String())
		exec.Command("/bin/sh", "-c", "docker stop "+match[1]).Run()
	}

	exec.Command("/bin/sh", "-c", "rm ./Dockerfile.integration").Run()
	exec.Command("/bin/sh", "-c", "rm ./test.yml").Run()
}
