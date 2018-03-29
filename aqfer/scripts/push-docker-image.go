package main

import (
	"os"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"log"
	"net/http"
	"net"
	"context"
	"io/ioutil"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"net/url"
	"encoding/json"
	"encoding/base64"
	"strings"
	"io"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

func usage() {
	fmt.Fprint(os.Stderr, "Usage aq-push-docker-image docker-image-name docker-image-version aws-region [ecr-repository]")
	os.Exit(1)
}

func fail(err error) {
	fmt.Fprint(os.Stderr, "error: %s", err.Error())
	os.Exit(2)
}

func main() {
	if len(os.Args) < 4 && len(os.Args) > 5 {
		usage()
	}

	imageName, imageVersion := os.Args[1], os.Args[2]
	awsRegion := os.Args[3]

	var repoName string
	if len(os.Args) == 5 {
		repoName = os.Args[4]
	} else {
		repoName = imageName
	}

	sess, err := session.NewSession(&aws.Config{Region: aws.String(awsRegion)})

	if err != nil {
		fail(fmt.Errorf("error establishing AWS session: %s", err.Error()))
	}

	ecrClient := ecr.New(sess)

	var repo *ecr.Repository
	dri := &ecr.DescribeRepositoriesInput{RepositoryNames: []*string{aws.String(repoName)}}
	dro, err := ecrClient.DescribeRepositories(dri)
	if err != nil {
		awsErr, ok := err.(awserr.Error)
		if !ok || awsErr.Code() != ecr.ErrCodeRepositoryNotFoundException {
			fail(fmt.Errorf("error getting repository information: %s", err.Error()))
		}
	} else if len(dro.Repositories) != 0 {
		repo = dro.Repositories[0]
	}

	if repo == nil {
		log.Printf("Repository not found. Creating repository: %s", repoName)
		cri := &ecr.CreateRepositoryInput{RepositoryName: aws.String(repoName)}
		cro, err := ecrClient.CreateRepository(cri)

		if err != nil {
			fail(fmt.Errorf("error creating new repository: %s", err.Error()))
		}
		repo = cro.Repository
	}
	repoUri := *repo.RepositoryUri
	log.Printf("Repository URI: %s", repoUri)

	gati := &ecr.GetAuthorizationTokenInput{RegistryIds: []*string{repo.RegistryId}}
	gato, err := ecrClient.GetAuthorizationToken(gati)
	if err != nil {
		fail(fmt.Errorf("error getting auth token: %s", err.Error()))
	}
	authToken := *gato.AuthorizationData[0].AuthorizationToken
	bb, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		fail(fmt.Errorf("error decoding auth token: %s", err.Error()))
	}
	s := string(bb)
	pos := strings.Index(s, ":")

	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}

	qs, err := json.Marshal(map[string][]string{"reference": {imageName + ":" + imageVersion}})
	if err != nil {
		fail(fmt.Errorf("error constructing image filter: %s", err.Error()))
	}
	inspectUrl := fmt.Sprintf("http://unix/images/json?filters=%s", url.QueryEscape(string(qs)))
	resp, err := httpc.Get(inspectUrl)
	if err != nil {
		fail(fmt.Errorf("error inspecting image: %s", err.Error()))
	}
	bb, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fail(fmt.Errorf("error reading image info: %s", err.Error()))
	}
	var imageId string
	if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		fail(fmt.Errorf("error reading image: %s", bb))
	} else {
		var images []struct {
			Id string
		}
		err := json.Unmarshal(bb, &images)
		if err != nil {
			fail(fmt.Errorf("error unmarshalling image: %s", err.Error()))
		}
		if len(images) == 0 {
			fail(fmt.Errorf("no such image: %s", imageName + ":" + imageVersion))
		}
		imageId = images[0].Id
	}

	tagUrl := fmt.Sprintf("http://unix/images/%s/tag?repo=%s&tag=%s", imageId, url.QueryEscape(repoUri), url.QueryEscape(imageVersion))
	resp, err = httpc.Post(tagUrl, "application/json", nil)
	if err != nil {
		fail(fmt.Errorf("error tagging image: %s", err.Error()))
	}
	if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		bb, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fail(fmt.Errorf("error reading tag response: %s", err.Error()))
		}
		fail(fmt.Errorf("error tagging image: %s", bb))
	}

	pushUrl := fmt.Sprintf("http://unix/images/%s/push?tag=%s", url.PathEscape(repoUri),
		url.QueryEscape(imageVersion))
	req, err := http.NewRequest("POST", pushUrl, nil)
	if err != nil {
		fail(err)
	}
	authConfig := struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serveraddress"`
	}{
		s[:pos], s[pos+1:], repoUri[:strings.Index(repoUri, "/")],
	}
	bb, err = json.Marshal(&authConfig)
	if err != nil {
		fail(fmt.Errorf("error marshalling auth config: %s", err.Error()))
	}
	auth := base64.StdEncoding.EncodeToString(bb)
	log.Printf("Auth: %s", auth)
	req.Header.Set("X-Registry-Auth", auth)
	resp, err = httpc.Do(req)
	if err != nil {
		fail(fmt.Errorf("error pushing image: %s", err.Error()))
	}
	log.Printf("Push status: %s", resp.StatusCode)
	if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		bb, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fail(fmt.Errorf("error reading push response: %s", err.Error()))
		}
		fail(fmt.Errorf("error pushing image: %s", bb))
	}
	buf := make([]byte, 1024)
	for ; ; {
		n, err := resp.Body.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				fail(fmt.Errorf("error reading push response: %s", err.Error()))
			}
		}
		fmt.Print(string(buf[:n]))
	}
	resp.Body.Close()
}
