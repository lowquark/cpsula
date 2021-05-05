#!/bin/bash

openssl genrsa -out pkey 2048
openssl req -new -key pkey -out cert.req
openssl x509 -req -days 365 -in cert.req -signkey pkey -out cert

