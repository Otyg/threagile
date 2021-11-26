#!/bin/bash
export GOOS=linux
go version
go mod tidy
go test ./...
go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o raa.so raa/raa/raa.go
go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o dummy.so raa/dummy/dummy.go
go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o demo-rule.so risks/custom/demo/demo-rule.go
go build -a -trimpath -ldflags="-s -w -X github.com/otyg/threagile/model.ThreagileVersion=$THREAGILE_VERSION -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -o threagile
