import platform
import shutil
import subprocess


class SystemInstaller:

    def __init__(self):
        self.os_name, self.pkg_manager = self._detect_system()

        self._commands = {
            "apt": ["sudo", "apt-get", "install", "-y"],
            "pacman": ["sudo", "pacman", "-S", "--noconfirm"],
            "yay": ["yay", "-S", "--noconfirm"],
            "paru": ["paru", "-S", "--noconfirm"],
            "dnf": ["sudo", "dnf", "install", "-y"],
            "brew": ["brew", "install"],
        }

    def _detect_system(self):
        os_type = platform.system()

        if os_type == "Windows":
            return "Windows", None

        elif os_type == "Darwin":
            return "macOS", "brew"

        elif os_type == "Linux":
            # Arch-based: prioriza AUR helper (yay/paru) sobre pacman puro
            if shutil.which("pacman"):
                if shutil.which("yay"):
                    return "Linux (Arch-based + yay)", "yay"
                elif shutil.which("paru"):
                    return "Linux (Arch-based + paru)", "paru"
                else:
                    return "Linux (Arch-based, pacman only)", "pacman"

            if shutil.which("apt"):
                return "Linux (Debian/Ubuntu-based)", "apt"

            if shutil.which("dnf"):
                return "Linux (Fedora/RHEL-based)", "dnf"

            # Fallback via freedesktop
            try:
                os_info = platform.freedesktop_os_release()
                distro_id = os_info.get("ID", "").lower()
                id_like = os_info.get("ID_LIKE", "").lower()

                if (
                    "debian" in distro_id
                    or "ubuntu" in distro_id
                    or "debian" in id_like
                ):
                    return "Linux (Debian/Ubuntu-like)", "apt"

                if "arch" in distro_id or "arch" in id_like:
                    if shutil.which("yay"):
                        return "Linux (Arch-like + yay)", "yay"
                    elif shutil.which("paru"):
                        return "Linux (Arch-like + paru)", "paru"
                    else:
                        return "Linux (Arch-like, pacman only)", "pacman"

                if "fedora" in distro_id or "rhel" in distro_id or "fedora" in id_like:
                    return "Linux (Fedora-like)", "dnf"

            except AttributeError:
                pass

            return "Linux (Unknown Distro)", "unknown"

        return "Unknown OS", None

    def install_packages(self, apps: list) -> bool:
        """Recebe uma lista de strings contendo os nomes das aplicações e executa a instalação."""
        if not apps:
            print("[-] Nenhum pacote foi enviado para a lista.")
            return False

        if not self.pkg_manager or self.pkg_manager == "unknown":
            print(
                f"[-] Erro: Nenhum gerenciador de pacotes suportado foi encontrado para {self.os_name}."
            )
            return False

        # apt: atualiza repositórios antes de instalar
        if self.pkg_manager == "apt":
            print("[*] Atualizando repositórios (apt-get update)...")
            try:
                subprocess.run(
                    ["sudo", "apt-get", "update"], check=True, stdout=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError:
                print(
                    "[-] Aviso: Falha ao atualizar repositórios, tentando instalar mesmo assim."
                )

        # pacman puro: aviso sobre AUR
        if self.pkg_manager == "pacman":
            print("[!] Aviso: Nenhum AUR helper (yay/paru) detectado.")
            print(
                "[!] Alguns pacotes podem não estar nos repositórios oficiais do pacman."
            )
            print("[!] Considere instalar yay ou paru para acesso completo ao AUR.\n")

        base_cmd = self._commands[self.pkg_manager]
        full_command = base_cmd + apps

        print(f"[*] Sistema Detectado: {self.os_name}")
        print(f"[*] Gerenciador: {self.pkg_manager}")
        print(f"[*] Executando comando: {' '.join(full_command)}\n")

        try:
            subprocess.run(full_command, check=True)
            print("\n[+] Todos os pacotes instalados com sucesso!")
            return True

        except subprocess.CalledProcessError as e:
            print(f"\n[-] Erro na execução do comando. Código de saída: {e.returncode}")
            return False
        except PermissionError:
            print("\n[-] Erro: Permissão negada para executar o comando.")
            return False
