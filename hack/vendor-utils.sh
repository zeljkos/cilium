#!/usr/bin/env bash
set -e

clone(){
    repo="https://${2}"
    tool="${1}"
    commit="${3}"

    proj_parent_dir=${repo%/*}
    proj_parent_dir=${proj_parent_dir#*//}
    proj_name=${repo##*/}

    echo "${proj_parent_dir}"
    echo "${proj_name}"

    mkdir -p "${proj_parent_dir}"
    cd "${proj_parent_dir}"
    if [ "${tool}" == "git" ]; then
        git clone "${repo}"
        cd "${proj_name}"
        if [ -n "${commit}" ]; then
            git reset --hard "${commit}"
        fi
    elif [ "${tool}" == hg ]; then
        hg clone "${repo}"
        cd "${proj_name}"
        if [ -n "${commit}" ]; then
            hg revert "${commit}"
        fi
    fi
}

clean_dir(){
    cd "${1}"
    rm -fr vendor
    mkdir vendor
}

