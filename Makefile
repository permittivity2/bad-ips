.PHONY: all clean deb install help

PACKAGE_NAME = bad-ips
VERSION = $(shell cat VERSION)
DEB_NAME = $(PACKAGE_NAME)_$(VERSION)_all.deb

help:
	@echo "Bad IPs Package Builder"
	@echo ""
	@echo "Targets:"
	@echo "  make deb     - Build .deb package using dpkg-buildpackage"
	@echo "  make clean   - Remove build artifacts"
	@echo "  make install - Install to local system (sudo required)"
	@echo "  make help    - Show this help message"
	@echo ""

all: deb

clean:
	dpkg-buildpackage -T clean 2>/dev/null || true
	rm -f $(DEB_NAME) $(PACKAGE_NAME)_*.dsc $(PACKAGE_NAME)_*.tar.xz $(PACKAGE_NAME)_*.changes
	@echo "Cleaned build artifacts"

deb:
	@echo "Building $(DEB_NAME)..."
	@echo ""
	fakeroot debian/rules clean
	fakeroot debian/rules binary
	@echo ""
	@echo ""
	@echo "==================================================================="
	@echo "SUCCESS: Built $(DEB_NAME)"
	@echo "==================================================================="
	@echo ""
	@echo "To install:"
	@echo "  sudo dpkg -i $(DEB_NAME)"
	@echo "  sudo apt-get install -f  # Install dependencies"
	@echo ""
	@echo "To test:"
	@echo "  dpkg-deb -I $(DEB_NAME)  # Show package info"
	@echo "  dpkg-deb -c $(DEB_NAME)  # List contents"
	@echo ""

install:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Must run as root (use sudo)"; \
		exit 1; \
	fi

	@if [ ! -f "$(DEB_NAME)" ]; then \
		echo "Error: $(DEB_NAME) not found. Run 'make deb' first."; \
		exit 1; \
	fi

	dpkg -i $(DEB_NAME)
	apt-get install -f -y

	@echo ""
	@echo "==================================================================="
	@echo "Installed $(PACKAGE_NAME) v$(VERSION)"
	@echo "==================================================================="
	@echo ""
	@echo "Next steps:"
	@echo "  1. Configure: sudo cp /usr/local/etc/badips.conf.hunter-template /usr/local/etc/badips.conf"
	@echo "  2. Edit: sudo nano /usr/local/etc/badips.conf"
	@echo "  3. Enable: sudo systemctl enable bad_ips.service"
	@echo "  4. Start: sudo systemctl start bad_ips.service"
	@echo ""
