# 编译器设置（顶层公共变量，子 Makefile 可按需覆盖）
CC = gcc

# 子目录构建顺序（common 必须先编译安装，plugin 的 daemon 依赖 libmqtt_common.so）
DIRS := common client plugin

# 默认目标：按顺序编译所有子目录
all:
	@echo "\033[32m===== Building common =====\033[0m"
	$(MAKE) -C common
	@echo "\n\033[32m===== Building client =====\033[0m"
	$(MAKE) -C client
	@echo "\n\033[32m===== Building plugin =====\033[0m"
	$(MAKE) -C plugin

# 清理所有子目录
clean:
	@for dir in $(DIRS); do \
		echo "\033[33mCleaning $$dir\033[0m"; \
		$(MAKE) -C $$dir clean; \
	done

# 安装（需要 root 权限）
install:
	@$(MAKE) -C common install
	@$(MAKE) -C plugin install

.PHONY: all clean install