#!/bin/bash

echo $(cat pom.xml | grep -m1 '<version>' | sed -E 's/.*<version>([^<]+)<\/version>.*/\1/')
