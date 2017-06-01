// Copyright 2015 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

// Program aedeploy assists with deploying App Engine "flexible environment" Go apps to production.
// A temporary directory is created; the app, its subdirectories, and all its
// dependencies from $GOPATH are copied into the directory; then the app
// is deployed to production with the provided command.
//
// The app must be in "package main".
//
// This command must be issued from within the root directory of the app
// (where the app.yaml file is located).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\t%s gcloud --verbosity debug app deploy --version myversion ./app.yaml\tDeploy app to production\n", os.Args[0])
}

var verbose bool

// vlogf logs to stderr if the "-v" flag is provided.
func vlogf(f string, v ...interface{}) {
	if !verbose {
		return
	}
	log.Printf("[aedeploy] "+f, v...)
}

func main() {
	flag.BoolVar(&verbose, "v", false, "Verbose logging.")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	notice := func() {
		fmt.Fprintln(os.Stderr, `NOTICE: aedeploy is deprecated. Just use "gcloud app deploy".`)
	}

	notice()
	if err := deploy(); err != nil {
		fmt.Fprintf(os.Stderr, os.Args[0]+": Error: %v\n", err)
		notice()
		fmt.Fprintln(os.Stderr, `You might need to update gcloud. Run "gcloud components update".`)
		os.Exit(1)
	}
	notice() // Make sure they see it at the end.
}

// deploy calls the provided command to deploy the app from the temporary directory.
func deploy() error {
	vlogf("Running command %v", flag.Args())
	cmd := exec.Command(flag.Arg(0), flag.Args()[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unable to run %q: %v", strings.Join(flag.Args(), " "), err)
	}
	return nil
}
