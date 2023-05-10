#!/usr/bin/env bash

_init() {
    shopt -s extglob

    ## Minimum required versions for build dependencies
    GIT_VERSION="1.0"
    GO_VERSION="1.20"
    OSX_VERSION="10.8"
    KNAME=$(uname -s)
    ARCH=$(uname -m)
    case "${KNAME}" in
        SunOS )
            ARCH=$(isainfo -k)
            ;;
    esac
}

check_minimum_version() {
    IFS='.' read -r -a varray1 <<< "$1"
    IFS='.' read -r -a varray2 <<< "$2"

    for i in "${!varray1[@]}"; do
        if [[ ${varray1[i]} -lt ${varray2[i]} ]]; then
            return 0
        elif [[ ${varray1[i]} -gt ${varray2[i]} ]]; then
            return 1
        fi
    done

    return 0
}

assert_is_supported_arch() {
    case "${ARCH}" in
        x86_64 | amd64 | ppc64le | aarch64 | arm* | s390x )
            return
            ;;
        *)
            echo "Arch '${ARCH}' is not supported. Supported Arch: [x86_64, amd64, ppc64le, aarch64, arm*, s390x]"
            exit 1
    esac
}

assert_is_supported_os() {
    case "${KNAME}" in
        Linux )
            return
            ;;
        *)
            echo "OS '${KNAME}' is not supported. Supported OS: Linux"
            exit 1
    esac
}

assert_check_golang_env() {
    if ! which go >/dev/null 2>&1; then
        echo "Cannot find go binary in your PATH configuration, please refer to Go installation document at https://golang.org/doc/install"
        exit 1
    fi

    installed_go_version=$(go version | sed 's/^.* go\([0-9.]*\).*$/\1/')
    if ! check_minimum_version "${GO_VERSION}" "${installed_go_version}"; then
        echo "Go runtime version '${installed_go_version}' is unsupported. Minimum supported version: ${GO_VERSION} to compile."
        exit 1
    fi
}

assert_check_deps() {
    # support unusual Git versions such as: 2.7.4 (Apple Git-66)
    installed_git_version=$(git version | perl -ne '$_ =~ m/git version (.*?)( |$)/; print "$1\n";')
    if ! check_minimum_version "${GIT_VERSION}" "${installed_git_version}"; then
        echo "Git version '${installed_git_version}' is not supported. Minimum supported version: ${GIT_VERSION}"
        exit 1
    fi
}

main() {
    ## Check for supported arch
    assert_is_supported_arch

    ## Check for supported os
    assert_is_supported_os

    ## Check for Go environment
    assert_check_golang_env

    ## Check for dependencies
    assert_check_deps
}

_init && main "$@"
