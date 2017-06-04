#!/bin/sh

mvn compile assembly:single
cp target/certutil-*.jar bin/
