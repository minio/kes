//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func genLDFlags(version string) string {
	var ldflagsStr string
	ldflagsStr = "-X github.com/minio/kes/cmd.Version=" + version + " "
	ldflagsStr = ldflagsStr + "-X github.com/minio/kes/cmd.ReleaseTag=" + releaseTag(version) + " "
	ldflagsStr = ldflagsStr + "-X github.com/minio/kes/cmd.CommitID=" + commitID() + " "
	ldflagsStr = ldflagsStr + "-X github.com/minio/kes/cmd.ShortCommitID=" + commitID()[:12]
	if depEnv := os.Getenv("DEPLOY_ENV"); depEnv != "development" {
		ldflagsStr = ldflagsStr + " -s -w"
	}
	return ldflagsStr
}

// genReleaseTag prints release tag to the console for easy git tagging.
func releaseTag(version string) string {
	relPrefix := "DEVELOPMENT"
	if prefix := os.Getenv("CALLHOME_LOGS_RELEASE"); prefix != "" {
		relPrefix = prefix
	}

	relTag := strings.Replace(version, " ", "-", -1)
	relTag = strings.Replace(relTag, ":", "-", -1)
	relTag = strings.Replace(relTag, ",", "", -1)
	return relPrefix + "." + relTag
}

// commitID returns the abbreviated commit-id hash of the last commit.
func commitID() string {
	// git log --format="%h" -n1
	var (
		commit []byte
		e      error
	)
	cmdName := "git"
	cmdArgs := []string{"log", "--format=%H", "-n1"}
	if commit, e = exec.Command(cmdName, cmdArgs...).Output(); e != nil {
		fmt.Fprintln(os.Stderr, "Error generating git commit-id: ", e)
		os.Exit(1)
	}

	return strings.TrimSpace(string(commit))
}

func main() {
	fmt.Println(genLDFlags(time.Now().UTC().Format(time.RFC3339)))
}
