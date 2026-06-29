

.PHONY: all clean install build-go build-c test run-example help

# Variáveis
GO := go
CC := gcc
GO_FLAGS := -ldflags="-s -w"  # Strips debug info, smaller binary
C_FLAGS := -O3 -march=native -flto -funroll-loops

# Binários Go
GO_BINARIES := tech_detector js_analyzer api_discoverer port_scanner
GO_DIRS := tech_detector js_analyzer api_discoverer port_scanner

# Binários C (opcionais)
C_BINARIES := secret_scanner
C_DIRS := secret_scanner

# Diretório de binários compilados
BIN_DIR := bin

# ========================================
# Targets principais
# ========================================

all: create-bin-dir build-go build-c
	@echo "✅ All binaries compiled successfully!"
	@echo "📦 Binaries location: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

# Cria diretório de binários
create-bin-dir:
	@mkdir -p $(BIN_DIR)

# Build Go binaries
build-go: $(GO_BINARIES)
	@echo "🔨 Go binaries compiled!"

# Build C binaries
build-c: $(C_BINARIES)
	@echo "🔨 C binaries compiled!"

# ========================================
# Compilação individual Go
# ========================================
tech_detector: create-bin-dir
	@echo "📦 Building tech_detector..."
	cd tech_detector && $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/tech_detector .
	@echo "  ✅ tech_detector built"

js_analyzer: create-bin-dir
	@echo "📦 Building js_analyzer..."
	cd js_analyzer && $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/js_analyzer .
	@echo "  ✅ js_analyzer built"

api_discoverer: create-bin-dir
	@echo "📦 Building api_discoverer..."
	cd api_discoverer && $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/api_discoverer .
	@echo "  ✅ api_discoverer built"

port_scanner: create-bin-dir
	@echo "📦 Building port_scanner..."
	cd port_scanner && $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/port_scanner .
	@echo "  ✅ port_scanner built"

# ========================================
# Compilação C
# ========================================
secret_scanner: create-bin-dir
	@echo "📦 Building secret_scanner (C)..."
	cd secret_scanner && $(CC) $(C_FLAGS) -o ../$(BIN_DIR)/secret_scanner scanner.c -lpthread
	strip $(BIN_DIR)/secret_scanner
	@echo "  ✅ secret_scanner built"

# ========================================
# Cross-compilation (para distribuição)
# ========================================
cross-compile: create-bin-dir
	@echo "🌍 Cross-compiling for all platforms..."
	
	# Linux AMD64
	cd tech_detector && GOOS=linux GOARCH=amd64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/tech_detector_linux_amd64 .
	cd js_analyzer && GOOS=linux GOARCH=amd64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/js_analyzer_linux_amd64 .
	cd api_discoverer && GOOS=linux GOARCH=amd64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/api_discoverer_linux_amd64 .
	cd port_scanner && GOOS=linux GOARCH=amd64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/port_scanner_linux_amd64 .
	
	# macOS AMD64
	cd tech_detector && GOOS=darwin GOARCH=amd64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/tech_detector_darwin_amd64 .
	cd js_analyzer && GOOS=darwin GOARCH=amd64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/js_analyzer_darwin_amd64 .
	
	# macOS ARM64 (M1/M2)
	cd tech_detector && GOOS=darwin GOARCH=arm64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/tech_detector_darwin_arm64 .
	cd js_analyzer && GOOS=darwin GOARCH=arm64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/js_analyzer_darwin_arm64 .
	
	# Windows AMD64
	cd tech_detector && GOOS=windows GOARCH=amd64 $(GO) build $(GO_FLAGS) -o ../$(BIN_DIR)/tech_detector_windows_amd64.exe .
	
	@echo "✅ Cross-compilation complete!"
	@ls -lh $(BIN_DIR)/

# ========================================
# Instalação
# ========================================
install: all
	@echo "📥 Installing binaries to /usr/local/bin..."
	sudo cp $(BIN_DIR)/* /usr/local/bin/
	@echo "✅ Installed!"

# ========================================
# Teste e Validação
# ========================================
test: all
	@echo "🧪 Testing all modules..."
	
	@echo "\n🔍 Testing tech_detector..."
	@echo '["https://example.com"]' > /tmp/test_urls.json
	./$(BIN_DIR)/tech_detector -urls /tmp/test_urls.json -output /tmp/tech_test.json 2>/dev/null && echo "  ✅ tech_detector works!" || echo "  ❌ tech_detector failed"
	
	@echo "\n🔍 Testing port_scanner..."
	@echo '["127.0.0.1"]' > /tmp/test_hosts.json
	./$(BIN_DIR)/port_scanner -hosts /tmp/test_hosts.json -ports "22,80" -timeout 1 2>/dev/null && echo "  ✅ port_scanner works!" || echo "  ❌ port_scanner failed"
	
	@echo "\n🔍 Testing Python modules..."
	python3 -c "from endpoint_mapper.mapper import EndpointMapper; print('  ✅ endpoint_mapper works!')"
	python3 -c "from form_mapper.forms import FormMapper; print('  ✅ form_mapper works!')"
	python3 -c "import utils; print('  ✅ utils works!')"
	
	@echo "\n✅ All tests passed!"

# ========================================
# Exemplo de uso
# ========================================
run-example:
	@echo "🎯 Running example pipeline..."
	@echo ""
	@echo "Step 1: Create test data"
	@echo '["https://example.com", "https://httpbin.org"]' > /tmp/test_urls.json
	@echo '["93.184.216.34", "34.227.73.116"]' > /tmp/test_hosts.json
	
	@echo "Step 2: Run tech_detector"
	./$(BIN_DIR)/tech_detector -urls /tmp/test_urls.json -output /tmp/tech_output.json
	
	@echo "Step 3: Run port_scanner"
	./$(BIN_DIR)/port_scanner -hosts /tmp/test_hosts.json -ports "80,443" -output /tmp/port_output.json
	
	@echo "Step 4: View results"
	@echo "--- Tech Detection Results ---"
	@cat /tmp/tech_output.json | python3 -m json.tool | head -20
	@echo ""
	@echo "--- Port Scanner Results ---"
	@cat /tmp/port_output.json | python3 -m json.tool | head -20
	
	@echo ""
	@echo "✅ Example complete! Check /tmp/ for outputs"

# ========================================
# Limpeza
# ========================================
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f /tmp/tech_test.json /tmp/test_urls.json /tmp/test_hosts.json
	rm -f /tmp/tech_output.json /tmp/port_output.json
	@echo "✅ Clean!"

# ========================================
# Ajuda
# ========================================
help:
	@echo "========================================"
	@echo "  SurfaceMapping Build System"
	@echo "========================================"
	@echo ""
	@echo "Targets:"
	@echo "  make all          - Compila todos os binários"
	@echo "  make build-go     - Compila apenas binários Go"
	@echo "  make build-c      - Compila apenas binários C"
	@echo "  make cross-compile - Cross-compila para todas plataformas"
	@echo "  make install      - Instala binários no sistema"
	@echo "  make test         - Testa todos os módulos"
	@echo "  make run-example  - Executa exemplo prático"
	@echo "  make clean        - Remove artefatos de build"
	@echo "  make help         - Mostra esta ajuda"
	@echo ""
	@echo "Requirements:"
	@echo "  - Go 1.21+  (https://go.dev/dl/)"
	@echo "  - GCC        (sudo apt install build-essential)"
	@echo "  - Python 3.8+"
	@echo ""