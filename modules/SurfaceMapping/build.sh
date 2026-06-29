#!/bin/bash
# ========================================
# SurfaceMapping - Build Script
# Compila e prepara todo o ecossistema
# ========================================

set -e  # Exit on error

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  SurfaceMapping Build Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Detecta sistema operacional
OS=$(uname -s)
ARCH=$(uname -m)
echo -e "${YELLOW}📋 System: $OS $ARCH${NC}"
echo ""

# Função para verificar dependências
check_dependencies() {
    echo -e "${YELLOW}🔍 Checking dependencies...${NC}"
    
    # Check Go
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}')
        echo -e "  ${GREEN}✅ Go: $GO_VERSION${NC}"
    else
        echo -e "  ${RED}❌ Go not found! Install from https://go.dev/dl/${NC}"
        exit 1
    fi
    
    # Check GCC (for C binaries)
    if command -v gcc &> /dev/null; then
        GCC_VERSION=$(gcc --version | head -n1)
        echo -e "  ${GREEN}✅ GCC: $GCC_VERSION${NC}"
    else
        echo -e "  ${YELLOW}⚠️  GCC not found - C binaries won't be built${NC}"
        echo -e "  ${YELLOW}   Install: sudo apt install build-essential${NC}"
    fi
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        echo -e "  ${GREEN}✅ $PYTHON_VERSION${NC}"
    else
        echo -e "  ${RED}❌ Python 3 not found!${NC}"
        exit 1
    fi
    
    # Check make
    if command -v make &> /dev/null; then
        echo -e "  ${GREEN}✅ make${NC}"
    else
        echo -e "  ${RED}❌ make not found! Install: sudo apt install make${NC}"
        exit 1
    fi
    
    echo ""
}

# Função para criar estrutura de diretórios
create_structure() {
    echo -e "${YELLOW}📁 Creating directory structure...${NC}"
    
    mkdir -p bin
    mkdir -p output
    
    echo -e "  ${GREEN}✅ Directories created${NC}"
    echo ""
}

# Função para compilar Go binários
build_go_binaries() {
    echo -e "${YELLOW}🔨 Building Go binaries...${NC}"
    
    local go_binaries=(
        "tech_detector"
        "js_analyzer" 
        "api_discoverer"
        "port_scanner"
    )
    
    for binary in "${go_binaries[@]}"; do
        if [ -d "$binary" ] && [ -f "$binary/main.go" ]; then
            echo -e "  ${BLUE}📦 Building $binary...${NC}"
            cd "$binary"
            
            # Inicializa go.mod se não existir
            if [ ! -f "go.mod" ]; then
                go mod init "buggy/$binary" 2>/dev/null || true
            fi
            
            # Build com flags de otimização
            go build -ldflags="-s -w" -o "../bin/$binary" .
            
            if [ $? -eq 0 ]; then
                echo -e "    ${GREEN}✅ $binary built successfully${NC}"
                echo -e "    📏 Size: $(du -h ../bin/$binary | cut -f1)"
            else
                echo -e "    ${RED}❌ Failed to build $binary${NC}"
                cd ..
                exit 1
            fi
            
            cd ..
        else
            echo -e "  ${YELLOW}⚠️  $binary not found, skipping...${NC}"
        fi
    done
    echo ""
}

# Função para compilar C binários
build_c_binaries() {
    echo -e "${YELLOW}🔨 Building C binaries...${NC}"
    
    if [ -d "secret_scanner" ] && [ -f "secret_scanner/scanner.c" ]; then
        echo -e "  ${BLUE}📦 Building secret_scanner...${NC}"
        cd secret_scanner
        
        gcc -O3 -march=native -flto -funroll-loops -o "../bin/secret_scanner" scanner.c -lpthread
        
        if [ $? -eq 0 ]; then
            strip ../bin/secret_scanner 2>/dev/null || true
            echo -e "    ${GREEN}✅ secret_scanner built successfully${NC}"
            echo -e "    📏 Size: $(du -h ../bin/secret_scanner | cut -f1)"
        else
            echo -e "    ${RED}❌ Failed to build secret_scanner${NC}"
            cd ..
            exit 1
        fi
        
        cd ..
    fi
    echo ""
}

# Função para verificar build
verify_build() {
    echo -e "${YELLOW}🧪 Verifying build...${NC}"
    
    local all_ok=true
    
    # Testa cada binário
    for binary in bin/*; do
        if [ -f "$binary" ] && [ -x "$binary" ]; then
            if file "$binary" | grep -q "executable"; then
                echo -e "  ${GREEN}✅ $(basename $binary) is executable${NC}"
            else
                echo -e "  ${RED}❌ $(basename $binary) is not executable${NC}"
                all_ok=false
            fi
        fi
    done
    
    # Testa importação Python
    echo -e "\n  ${BLUE}Testing Python modules...${NC}"
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from utils import make_request, load_json, save_json
    print('    ✅ utils.py')
except Exception as e:
    print(f'    ❌ utils.py: {e}')

try:
    from endpoint_mapper.mapper import EndpointMapper
    print('    ✅ endpoint_mapper')
except Exception as e:
    print(f'    ❌ endpoint_mapper: {e}')

try:
    from form_mapper.forms import FormMapper
    print('    ✅ form_mapper')
except Exception as e:
    print(f'    ❌ form_mapper: {e}')

try:
    from surface import SurfaceMapper
    print('    ✅ surface.py')
except Exception as e:
    print(f'    ❌ surface.py: {e}')
"
    
    echo ""
    if $all_ok; then
        echo -e "${GREEN}✅ All verifications passed!${NC}"
    else
        echo -e "${RED}❌ Some verifications failed${NC}"
    fi
}

# Função para criar script de execução rápida
create_runner() {
    echo -e "${YELLOW}📝 Creating quick runner script...${NC}"
    
    cat > run_surface.sh << 'EOF'
#!/bin/bash
# Quick runner for SurfaceMapping
BIN_DIR="$(dirname "$0")/bin"

# Add bin directory to PATH
export PATH="$BIN_DIR:$PATH"

# Run surface mapping
python3 surface.py "$@"
EOF
    
    chmod +x run_surface.sh
    echo -e "  ${GREEN}✅ Created run_surface.sh${NC}"
    echo ""
}

# Função principal
main() {
    check_dependencies
    create_structure
    build_go_binaries
    build_c_binaries
    verify_build
    create_runner
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Build Complete! 🚀${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "Binaries location: ${BLUE}$(pwd)/bin/${NC}"
    echo ""
    echo -e "Quick start:"
    echo -e "  ${YELLOW}./run_surface.sh${NC}                    # Run with default config"
    echo -e "  ${YELLOW}./bin/tech_detector -help${NC}           # See tech_detector options"
    echo -e "  ${YELLOW}./bin/port_scanner -help${NC}            # See port_scanner options"
    echo ""
    echo -e "To install system-wide:"
    echo -e "  ${YELLOW}sudo make install${NC}"
    echo ""
}

# Executa main
main