package main

import (
	"os"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"strings"
	"sort"
	"strconv"
	"regexp"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage aq-ecr-get-next-version docker-image-name aws-region [ecr-repository]")
	os.Exit(1)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %s", err.Error())
	os.Exit(2)
}

func versionSort(versions sort.StringSlice) sort.StringSlice {
	sort.SliceStable(versions, func(i, j int) bool {
		a := strings.Split(versions[i], ".")
		b := strings.Split(versions[j], ".")
		for k, ak := range a {
			if k >= len(b) {
				return true
			}
			x, _ := strconv.Atoi(ak)
			y, _ := strconv.Atoi(b[k])
			if x > y {
				return true
			}
			if x < y {
				return false
			}
		}
		return false
	})
	return versions
}

func main() {
	if len(os.Args) < 4 && len(os.Args) > 5 {
		usage()
	}

	imageName := os.Args[1]
	majorVersion := os.Args[2]
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

	lii := &ecr.ListImagesInput{RepositoryName: aws.String(repoName), Filter:&ecr.ListImagesFilter{TagStatus: aws.String("TAGGED")}}
	lio, err := ecrClient.ListImages(lii)
	if err != nil {
		fail(fmt.Errorf("error listing images on repository: %s", err.Error()))
	}

	var tags []string
	versionPattern := regexp.MustCompile(fmt.Sprintf(`\A%s\.\d+\.\d+\z`, majorVersion))

	for _, img :=range lio.ImageIds {
		tag := *img.ImageTag
		if versionPattern.MatchString(tag) {
			tags = append(tags, tag)
		}
	}
	tags = versionSort(tags)
	var nextVersion string
	if len(tags) == 0 {
		nextVersion = "0.0.0"
	} else {
		last := tags[0]
		s := strings.Split(last, ".")
		v, _ := strconv.Atoi(s[1])
		s[1] = strconv.Itoa(v + 1)
		s[2] = "0"
		nextVersion = strings.Join(s, ".")
	}
	fmt.Printf("%s", nextVersion)
}
