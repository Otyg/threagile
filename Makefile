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

PHONY := $(TARGET)
$(TARGET): $(OBJS)
	GOOS=linux go version
	GOOS=linux go mod tidy
	GOOS=linux go test ./...
	GOOS=linux $(CC) $(FLAGS) ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} ${BUILDMODE} -o raa.so raa/raa/raa.go
	GOOS=linux $(CC) $(FLAGS) ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} ${BUILDMODE} -o dummy.so raa/dummy/dummy.go
	GOOS=linux $(CC) $(FLAGS) -ldflags="-s -w -X github.com/otyg/threagile/model.ThreagileVersion=$(shell echo -n $$THREAGILE_VERSION) -X main.buildTimestamp=$(shell date '+%Y%m%d%H%M%S')" ${GCFLAGS} ${ASMFLAGS} -o threagile


$(PLUGIN_DIR)/%.so:%.go
	GOOS=linux $(CC) $(FLAGS) ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} ${BUILDMODE} -o ${PLUGIN_DIR}${@F} $<

PHONY += clean
clean:
	rm -rf $(PLUGIN_DIR)/*

PHONY += echoes
echoes:
	@echo "SRC files: $(SRCS)"
	@echo "OBJ files: $(OBJS)"
	
.PHONY = $(PHONY)
