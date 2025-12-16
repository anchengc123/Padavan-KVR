include $(ROOTDIR)/coustom
THISDIR = $(shell pwd)

Xray_VERSION := 1.5.3
Xray_URL := https://codeload.github.com/XTLS/Xray-core/tar.gz/v$(Xray_VERSION)
Xray_dir = xray-core/Xray-core-$(Xray_VERSION)/main

# --- 新增：定义本地 Go 1.17 相关变量 ---
# 固件编译通常在 Linux x86_64 环境下进行 (GitHub Action 也是)
GO_VER := 1.17.13
GO_TAR := go$(GO_VER).linux-amd64.tar.gz
GO_DL_URL := https://go.dev/dl/$(GO_TAR)
# 定义本地 Go 的安装目录
LOCAL_GO_DIR := $(THISDIR)/go-portable
# 定义要使用的 Go 编译器路径
MY_GO := $(LOCAL_GO_DIR)/go/bin/go
# -----------------------------------

# 修改点: all 目标增加 deploy_go 依赖
all: download_xray build_extract deploy_go build_Xray

download_xray:
	( if [ ! -f $(THISDIR)/Xray-core-$(Xray_VERSION).tar.gz ]; then \
	curl --create-dirs -L $(Xray_URL) -o $(THISDIR)/Xray-core-$(Xray_VERSION).tar.gz ; \
	fi )

build_extract:
	mkdir -p $(THISDIR)/xray-core
	mkdir -p $(THISDIR)/bin
	( if [ ! -d $(THISDIR)/xray-core/Xray-core-$(Xray_VERSION) ]; then \
	rm -rf $(THISDIR)/xray-core/* ; \
	tar zxfv $(THISDIR)/Xray-core-$(Xray_VERSION).tar.gz -C $(THISDIR)/xray-core ; \
	fi )

# --- 新增：下载并解压专用 Go 环境 ---
deploy_go:
	( if [ ! -f $(MY_GO) ]; then \
		echo "Downloading Go $(GO_VER) for Xray compilation..." ; \
		mkdir -p $(LOCAL_GO_DIR) ; \
		curl -L $(GO_DL_URL) -o $(THISDIR)/$(GO_TAR) ; \
		tar -xzf $(THISDIR)/$(GO_TAR) -C $(LOCAL_GO_DIR) ; \
		rm -f $(THISDIR)/$(GO_TAR) ; \
	fi )

build_Xray:
	( cd $(THISDIR)/$(Xray_dir); \
	if [ "$(GOPROXY_ON)" = "y" ]; then \
	$(MY_GO) env -w GOPROXY=https://goproxy.cn,direct ; \
	fi ; \
	echo "Compiling using: $($(MY_GO) version)" ; \
	GOOS=linux GOARCH=mipsle $(MY_GO) build -ldflags "-w -s" -o $(THISDIR)/bin/xray; \
	)
	# 复制到 images 目录以便上传
	if [ -d /opt/images ]; then \
		cp -f $(THISDIR)/bin/xray /opt/images/xray-linux-mipsle; \
		echo "Xray binary copied to /opt/images/"; \
	fi

clean:
#	rm -rf $(THISDIR)/xray-core
#	rm -rf $(THISDIR)/bin
#	rm -rf $(LOCAL_GO_DIR)

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/bin/xray /usr/bin/v2ray
