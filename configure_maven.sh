#!/bin/bash

if [ -z "${ARTIFACTORY_DOMAIN}" ]; then
    echo "Environment variable ARTIFACTORY_DOMAIN is not set. Aborting ..."
    exit 1
fi

if [ -z "${ARTIFACTORY_USERNAME}" ]; then
    echo "Environment variable ARTIFACTORY_USERNAME is not set. Aborting ..."
    exit 2
fi

if [ -z "${ARTIFACTORY_PASSWORD}" ]; then
    echo "Environment variable ARTIFACTORY_PASSWORD is not set. Aborting ..."
    exit 3
fi

if [ -z "${SONAR_DOMAIN}" ]; then
    echo "Environment variable SONAR_DOMAIN is not set. Aborting ..."
    exit 4
fi

if [ -z "${SONAR_LOGIN}" ]; then
    echo "Environment variable SONAR_LOGIN is not set. Aborting ..."
    exit 5
fi

if [ -z "${SONATYPE_OSSRH_REPO_USERNAME}" ]; then
    echo "Environment variable SONATYPE_OSSRH_REPO_USERNAME is not set. Aborting ..."
    exit 6
fi

if [ -z "${SONATYPE_OSSRH_REPO_TOKEN}" ]; then
    echo "Environment variable SONATYPE_OSSRH_REPO_TOKEN is not set. Aborting ..."
    exit 7
fi

mkdir -p ~/.m2

cp settings.xml.tmpl ~/.m2/settings.xml
