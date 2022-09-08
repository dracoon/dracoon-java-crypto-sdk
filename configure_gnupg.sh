#!/bin/bash

if [ -z "${SONATYPE_OSSRH_SIGN_SECRING}" ]; then
    echo "Environment variable SONATYPE_OSSRH_SIGN_SECRING is not set. Aborting ..."
    exit 1
fi

if [ -z "${SONATYPE_OSSRH_SIGN_PUBRING}" ]; then
    echo "Environment variable SONATYPE_OSSRH_SIGN_PUBRING is not set. Aborting ..."
    exit 2
fi

if [ -z "${SONATYPE_OSSRH_SIGN_KEY_PASSPHRASE}" ]; then
    echo "Environment variable SONATYPE_OSSRH_SIGN_KEY_PASSPHRASE is not set. Aborting ..."
    exit 3
fi

mkdir -p ~/.gnupg

echo $SONATYPE_OSSRH_SIGN_SECRING | base64 --decode --ignore-garbage > ~/.gnupg/ossrh_secring.gpg
echo $SONATYPE_OSSRH_SIGN_PUBRING | base64 --decode --ignore-garbage > ~/.gnupg/ossrh_pubring.gpg

gpg --no-permission-warning --batch --passphrase $SONATYPE_OSSRH_SIGN_KEY_PASSPHRASE --import ~/.gnupg/ossrh_secring.gpg
gpg --no-permission-warning --batch --import ~/.gnupg/ossrh_pubring.gpg

