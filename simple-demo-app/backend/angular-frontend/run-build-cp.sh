#!/bin/bash

rm -rf ./dist/
ng build 

rm -rf ./../public/*
cp -r ./dist/angular-frontend/browser/* ./../public/