#!/bin/bash

sonarUrl="https://${SONAR_DOMAIN}"

version=$(./get_version_string.sh)

gitCommitHash=$CI_COMMIT_SHORT_SHA
if [ -z "${gitCommitHash}" ]; then
    gitCommitHash='-'
fi

gitBranchName=$CI_COMMIT_REF_NAME
if [ -z "${gitBranchName}" ]; then
    gitBranchName='-'
fi

sonar-scanner \
    -Dsonar.host.url=$sonarUrl \
    -Dsonar.projectVersion=$version \
    -Dsonar.scm.revision=$gitCommitHash \
    -Dsonar.branch.name=$gitBranchName
