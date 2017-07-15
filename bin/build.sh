#!/bin/sh -x

mvn compile assembly:single
cp target/certutil-*with*.jar bin/certutil.jar
