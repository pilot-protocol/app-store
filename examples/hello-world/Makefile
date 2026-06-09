.PHONY: bundle clean install-local uninstall

# bundle assembles a ready-to-install bundle under ./bundle/. The
# committed manifest.json is the template; the build output (with
# binary.sha256 pinned to the freshly-built binary) lives under
# bundle/ so re-runs never rewrite the committed file.
BUNDLE_DIR := bundle

bundle: $(BUNDLE_DIR)/bin/hello $(BUNDLE_DIR)/manifest.json

$(BUNDLE_DIR)/bin/hello: cmd/hello/main.go
	@mkdir -p $(BUNDLE_DIR)/bin
	go build -o $(BUNDLE_DIR)/bin/hello ./cmd/hello

# Copy the template manifest into the bundle, then pin the binary's
# actual sha256. python3 is on every dev box this project supports;
# no jq dependency.
$(BUNDLE_DIR)/manifest.json: manifest.json $(BUNDLE_DIR)/bin/hello
	@cp manifest.json $(BUNDLE_DIR)/manifest.json
	@SHA=$$(shasum -a 256 $(BUNDLE_DIR)/bin/hello | awk '{print $$1}'); \
	  python3 -c "import json,sys;p=json.load(open('$(BUNDLE_DIR)/manifest.json'));p['binary']['sha256']='$$SHA';json.dump(p,open('$(BUNDLE_DIR)/manifest.json','w'),indent=2)"; \
	  echo "bundled at $(BUNDLE_DIR)/ (binary sha256: $$SHA)"

# install-local sideloads the bundle into the local daemon's install
# root. Requires pilotctl on $PATH. The --local flag is required
# because the manifest is not catalogue-signed.
install-local: bundle
	pilotctl appstore install $(CURDIR)/$(BUNDLE_DIR) --local

uninstall:
	pilotctl appstore uninstall io.example.hello --yes

clean:
	rm -rf $(BUNDLE_DIR)
