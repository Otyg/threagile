TARGET = threagile
CC = go build
FLAGS = -a -trimpath
LDFLAGS = -ldflags="-s -w -X main.buildTimestamp=$(shell date '+%Y%m%d%H%M%S')"
GCFLAGS = -gcflags="all=-trimpath=/src"
ASMFLAGS = -asmflags="all=-trimpath=/src"
BUILDMODE = -buildmode=plugin

SUBDIR = risks
PLUGIN_DIR = risk-plugins/

SRCS = $(foreach fd, $(SUBDIR), $(wildcard $(fd)/**/*.go))
NODIR_SRC = $(notdir $(SRCS))
OBJS = $(addprefix $(PLUGIN_DIR)/, $(SRCS:go=so)) # obj/xxx.o obj/folder/xxx .o
all: threagile

threagile:
	GOOS=linux go version
	GOOS=linux go mod tidy
	GOOS=linux go test ./...
	GOOS=linux $(CC) $(FLAGS) ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} ${BUILDMODE} -o raa.so raa/raa/raa.go
	GOOS=linux $(CC) $(FLAGS) ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} ${BUILDMODE} -o dummy.so raa/dummy/dummy.go
	GOOS=linux $(CC) $(FLAGS) -ldflags="-s -w -X github.com/otyg/threagile/model.ThreagileVersion=$(shell echo -n $$THREAGILE_VERSION) -X main.buildTimestamp=$(shell date '+%Y%m%d%H%M%S')" ${GCFLAGS} ${ASMFLAGS} -o threagile