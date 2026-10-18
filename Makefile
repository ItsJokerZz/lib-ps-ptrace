NAME    := ptrace
VERSION := 1.0.0
LIB     := lib$(NAME).a

override PLATFORM := $(strip $(subst PS5,ps5,$(subst PS4,ps4,$(PLATFORM))))

ifeq ($(PLATFORM),)

SDKS := $(strip $(if $(PS4_PAYLOAD_SDK),ps4) $(if $(PS5_PAYLOAD_SDK),ps5))

.PHONY: all ps4 ps5 install install-ps4 install-ps5 clean

all install:
	@test -n "$(SDKS)" || { \
		echo "Neither PS4_PAYLOAD_SDK nor PS5_PAYLOAD_SDK is defined" >&2; \
		exit 1; }
	@for platform in $(SDKS); do \
		$(MAKE) --no-print-directory PLATFORM=$$platform $@ || exit 1; \
	done

ps4 ps5:
	@$(MAKE) --no-print-directory PLATFORM=$@ all

install-ps4 install-ps5:
	@$(MAKE) --no-print-directory PLATFORM=$(patsubst install-%,%,$@) install

clean:
	rm -rf build

else ifeq ($(PLATFORM),ps4)

ifndef PS4_PAYLOAD_SDK
    $(error PS4_PAYLOAD_SDK is undefined)
endif

include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk

ARCH    := -mstackrealign

else ifeq ($(PLATFORM),ps5)

ifndef PS5_PAYLOAD_SDK
    $(error PS5_PAYLOAD_SDK is undefined)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

ARCH    :=

else

$(error Unknown PLATFORM '$(PLATFORM)', expected ps4 or ps5)

endif

ifneq ($(PLATFORM),)

SOURCES := src/ptrace.c
BUILD   ?= build/$(PLATFORM)
OPT     ?= -O2
OBJECTS := $(SOURCES:src/%.c=$(BUILD)/%.o)
CFLAGS  := -std=gnu11 $(OPT) $(ARCH) -fPIC -ffunction-sections -fdata-sections
CFLAGS  += -Wall -Wextra -Werror -Iinclude -MMD -MP $(if $(DEBUG),-g)

.PHONY: all install clean

all: $(BUILD)/$(LIB)

$(BUILD)/$(LIB): $(OBJECTS)
	@mkdir -p $(dir $@)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

install: $(BUILD)/$(LIB)
	install -d $(DESTDIR)$(PREFIX)/include $(DESTDIR)$(PREFIX)/lib/pkgconfig
	install -m 644 include/ptrace.h $(DESTDIR)$(PREFIX)/include/ptrace.h
	install -m 644 $< $(DESTDIR)$(PREFIX)/lib/$(LIB)
	sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@VERSION@|$(VERSION)|' \
		$(NAME).pc.in > $(DESTDIR)$(PREFIX)/lib/pkgconfig/$(NAME).pc

clean:
	rm -rf $(BUILD)

-include $(OBJECTS:.o=.d)

endif
