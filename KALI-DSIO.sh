#!/usr/bin/env bash
# ============================================================
#  KALI-DSIO v1.7 · Preparación automática de Kali Linux (VM o física)
#  Uso:      sudo ./KALI-DSIO.sh [--si] [--simular]
#            kali-dsio --herramientas   (solo pipx, bbot y ~/Herramientas)
#            kali-dsio --marca-usuario  (sin root, tras la instalación)
#  Fases:    cursor · idioma · teclado · actualización · invitado
#            · pipx/bbot · limpieza · optimización XFCE/sistema · identidad DragonJAR
#
#  v1.7 (icono menú):
#   - Whisker Menu: button-icon pasa a "dragonjar-menu" (icono PROPIO de la
#     marca; sobrevive a cambios de tema y a reinstalaciones de kali-themes).
#   - _pisar_iconos_menu_en: sobrescribe TODAS las copias existentes de
#     kali-menu*.svg / kali-panel-menu*.svg dentro del tema activo (vía find)
#     porque temas como Flat-Remix duplican el icono en status/scalable/512,
#     ruta que GANA el best-match de GTK para tamaños 32-64px.
#   - _limpiar_iconos_basura_en: elimina el directorio "scalable/apps" que
#     el script creaba por error en temas que no lo declaran (no afecta a GTK
#     pero ensucia el árbol y confunde a futuras corridas).
#
#  --- Herramientas de la fase de reconocimiento (instalar_herramientas) ---
#  pipx + bbot ........... orquestador OSINT/recon multipaso (pipx aislado)
#  p0f .................... fingerprinting pasivo de SO por análisis de SYN
#  NetExec (nxc) ......... ejecución/postexplotación AD/SMB/RDP/SSH/WinRM
#  URLCrazy ............... typosquatting/homoglyphs/bitsquatting por dominio
#  apache-scalp ........... analizador de logs de ataque Apache/Nginx
#                          (Scalp!/Anathema, firmas PHPIDS + modernas; CLI
#                          'scalp' vía pipx + python3-regex)
#  git-dumper ............. dumpea repositorios .git expuestos en sitios web
#  hashcat/wordlists/dirb . crack de MD5 del lab CRYPTO-FAILURES y wordlist
#                          dirb/common.txt de gobuster (manuales /var/www/html)
#  trivy .................. scanner de CVEs en dependencias (lab SUPPLY-CHAIN)
#  pip-audit .............. auditor de paquetes Python (lab SUPPLY-CHAIN, pipx)
#  Greenbone GVM (OpenVAS) escáner de vulnerabilidades full stack (gvmd +
#                          openvas-scanner + gsad web UI + gvm-setup/start/stop).
#                          Servicios deshabilitados en el arranque: usar
#                          ~/Herramientas/greenbone.sh start|stop|status
#  chrome-devtools-mcp .... MCP de Chrome DevTools para automatización de navegador
#  computer-use-linux ..... MCP Rust (vía npm wrapper) para automatizar el propio
#                           escritorio Linux (AT-SPI, portal RemoteDesktop,
#                           ydotoold/xdotool; soporta Wayland y X11/XFCE).
#                           Requiere at-spi2-core + xdotool + wmctrl en X11.
#  opencode ............... CLI de asistencia IA en código (modelo DragonJAR-IA)
#  ~/Herramientas/ ........ eValidator.py, Cateyes.jpg, wayback_subdomains.sh,
#                          NmapDataExtractor.py, prueba.xml,
#                          nmap-parse-output (ernw), greenbone.sh,
#                          labs.sh (start|stop|status|open|urls para apache2),
#                          ocloop (harness de bucles para opencode, Bun),
#                          cupp (git), git-dumper (git), enlaces web
# ============================================================
set -u -o pipefail

VERSION="1.7"
SIMULAR=0
ASUMIR_SI=0
SOLO_MARCA=0
SOLO_HERRAMIENTAS=0
SESION_GRAFICA=0

# No preguntar nunca en TTY: dpkg y needrestart resuelven solos
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
 
BASE_MARCA="https://www.dragonjar.org/wp-content/uploads/2026/06"
DIR_TMP_MARCA="/tmp/KALI-DSIO-marca"
DIR_ASSETS="/usr/local/share/kali-dsio"
DIR_FUENTES="/usr/local/share/fonts/dragonjar"
# opencode: ruta del binario y del icono oficial (home del usuario real)
ICONO_OPENCODE_URL="https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/opencode-dark.png"
ICONO_OPENCODE_REL=".local/share/icons/hicolor/128x128/apps/opencode.png"
# Icono del botón del menú de inicio: nombre PROPIO (no colisiona con
# kali-menu/kali-panel-menu que los temas como Flat-Remix redistribuyen en
# varias subcarpetas con prioridad GTK distinta a la de apps/scalable).
ICONO_MENU_PROPIO="dragonjar-menu"
PANEL_DIR_REL=".config/xfce4/panel"
# Paquete npm del MCP computer-use-linux (wrapper de los binarios Rust
# computer-use-linux + computer-use-linux-cosmic). El binario expone un
# servidor MCP stdio (`computer-use-linux mcp`) con 18 herramientas para
# automatizar el escritorio local (screenshots, AT-SPI, input, ventanas).
CUL_NPM_PKG="@agent-sh/computer-use-linux"
CUL_BIN="computer-use-linux"
 
for arg in "$@"; do
  case "$arg" in
    --simular|--simulacion) SIMULAR=1 ;;
    --si|--asumir-si)       ASUMIR_SI=1 ;;
    --herramientas|herramientas) SOLO_HERRAMIENTAS=1 ;;
    --marca-usuario)        SOLO_MARCA=1 ;;
    -h|--help|ayuda)        echo "Uso: sudo $0 [--si] [--simular]  ·  solos: $0 --herramientas | --marca-usuario"; exit 0 ;;
    *) echo "Opción desconocida: $arg (ayuda: $0 --help)"; exit 2 ;;
  esac
done
 
if [[ $SIMULAR -eq 0 && $SOLO_MARCA -eq 0 && $SOLO_HERRAMIENTAS -eq 0 ]] && [[ $EUID -ne 0 ]]; then
  exec sudo "$0" "$@"
fi
 
_col() {  # $1 RRGGBB del manual de marca · $2 código ANSI de fallback
  # El chequeo de tty lo hace el bloque que nos llama (aquí stdout es $( ) y nunca es tty)
  if [[ "${COLORTERM:-}" == truecolor ]]; then
    printf '\e[38;2;%d;%d;%dm' "$((16#${1:0:2}))" "$((16#${1:2:2}))" "$((16#${1:4:2}))"
  else
    printf '\e[%sm' "$2"
  fi
}

if [[ -t 1 ]]; then
  R=$'\e[0m' B=$'\e[1m' DIM=$'\e[2m' VERDE=$'\e[32m'
  # Paleta del manual de marca: C11B05 acento/títulos · FBB03B avisos (Medio)
  # 40A9F6 info (Bajo) · 4A4A4A gris táctico (simulados)
  ROJO="$(_col C11B05 31)"
  AMARILLO="$(_col FBB03B 33)"
  AZUL="$(_col 40A9F6 34)"
  GRIS="$(_col 4A4A4A 90)"
else
  R="" B="" DIM="" VERDE="" ROJO="" AMARILLO="" AZUL="" GRIS=""
fi
 
USUARIO_REAL="${SUDO_USER:-${USER:-root}}"
HOME_REAL="$(getent passwd "$USUARIO_REAL" 2>/dev/null | cut -d: -f6)"
HOME_REAL="${HOME_REAL:-/home/$USUARIO_REAL}"

# ============================================================================
#  _detectar_sistema: preámbulo único que normaliza TODA la detección del
#  entorno en variables canónicas (KDSIO_*). Antes cada bloque re-detectaba
#  arch/virt/DE/sesión por su cuenta con esquemas mezclados (dpkg vs uname)
#  — exactamente lo contrario de DRY y origen de bugs (gospider matcheando
#  amd64|x86_64 a la defensiva porque _instalar_enumerathor ya mezclaba).
#
#  Exporta:
#    KDSIO_ARCH    : amd64|arm64|armhf|i386  (siempre esquema Debian)
#    KDSIO_ARCHRAW : mismo valor crudo de dpkg --print-architecture
#    KDSIO_VIRT    : none|kvm|qemu|vmware|... (systemd-detect-virt)
#    KDSIO_DE      : xfce|gnome|unknown
#    KDSIO_SESION  : x11|wayland|headless
#    KDSIO_MEM_MB  : entero (MemTotal /proc/meminfo)
#    KDSIO_NCPU    : entero (nproc)
#    KDSIO_DISCO_MB: entero (libre en /)
#    KDSIO_RED     : ok|caida (prueba DNS kali.org)
#  Idempotente: si las variables ya están pobladas, retorna sin tocar nada.
#  NO usar como función normal — solo llamar al inicio del main().
# ============================================================================
_detectar_sistema() {
  [[ -n "${KDSIO_ARCH:-}" ]] && return 0

  # --- Arquitectura: preferir dpkg (esquema Debian, estable), fallback uname.
  local raw
  raw="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  KDSIO_ARCHRAW="$raw"   # crudo, para logs de diagnóstico (dpkg vs uname)
  case "$raw" in
    amd64|x86_64)        KDSIO_ARCH=amd64 ;;
    arm64|aarch64)       KDSIO_ARCH=arm64 ;;
    armhf|armv7l|armv7)  KDSIO_ARCH=armhf ;;
    i386|i686)           KDSIO_ARCH=i386 ;;
    *)                   KDSIO_ARCH=unknown ;;
  esac

  # --- Hipervisor: systemd-detect-virt (en física imprime "none" + rc=1).
  KDSIO_VIRT="$(systemd-detect-virt 2>/dev/null || true)"
  [[ -z "$KDSIO_VIRT" ]] && KDSIO_VIRT="none"

  # --- Escritorio: XDG_CURRENT_DESKTOP (sesión) + paquetes instalados.
  KDSIO_DE=unknown
  if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]]; then
    case "${XDG_CURRENT_DESKTOP,,}" in
      *xfce*) KDSIO_DE=xfce ;;
      *gnome*) KDSIO_DE=gnome ;;
      *kde*)   KDSIO_DE=kde ;;
      *)       KDSIO_DE=unknown ;;
    esac
  fi
  command -v xfconf-query >/dev/null 2>&1 && KDSIO_DE=xfce
  command -v gsettings    >/dev/null 2>&1 && [[ "$KDSIO_DE" == "unknown" ]] && KDSIO_DE=gnome

  # --- Sesión gráfica: wayland si WAYLAND_DISPLAY, si no x11 con DISPLAY, si no headless.
  if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
    KDSIO_SESION=wayland
  elif [[ -n "${DISPLAY:-}" ]] || [[ -S /tmp/.X11-unix/X0 ]] || [[ -n "$(find /tmp/.X11-unix -maxdepth 1 -type s -name 'X*' 2>/dev/null)" ]]; then
    KDSIO_SESION=x11
  else
    KDSIO_SESION=headless
  fi

  # --- Recursos: RAM, CPU, disco. /proc siempre presente en Linux.
  KDSIO_MEM_MB=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
  KDSIO_MEM_MB=${KDSIO_MEM_MB:-0}
  KDSIO_NCPU=$(nproc 2>/dev/null || echo 1)
  # df -Pm / | awk: bloque 1 GB (libre) en MB. Fallback a 0 si df falla.
  KDSIO_DISCO_MB=$(df -Pm / 2>/dev/null | awk 'NR==2{print $4}')
  KDSIO_DISCO_MB=${KDSIO_DISCO_MB:-0}

  # --- Red: ¿hay DNS funcional? Define KDSIO_RED=ok|caida para que los
  # bloques de descarga puedan elegir estrategia (full vs. degradado).
  if timeout 8 getent ahostsv4 kali.org >/dev/null 2>&1; then
    KDSIO_RED=ok
  else
    KDSIO_RED=caida
  fi

  # Compatibilidad con la lógica existente (no rompe consumidores legacy).
  VIRTUALIZACION="$KDSIO_VIRT"
  case "$KDSIO_VIRT" in
    none)        ETIQUETA_VIRT="física" ;;
    *)           ETIQUETA_VIRT="hipervisor $KDSIO_VIRT" ;;
  esac

  return 0
}

_detectar_sistema
REGISTRO="/var/log/KALI-DSIO-$(date +%Y%m%d-%H%M%S).log"
touch "$REGISTRO" 2>/dev/null || REGISTRO="/dev/null"
 
TOTAL_PASOS=0; PASOS_OK=0; PASOS_FALLIDOS=0; SIMULADOS=0; PASO_ACTUAL=0
declare -a NOMBRES_FALLIDOS=()
# La barra de progreso se dibuja en la línea inferior (sin '\n') y se limpia
# siempre antes de imprimir un mensaje de flujo, para que nunca se mezcle.
LINEA_PROGRESO=0

_tty() { [[ -t 1 ]]; }

_cerrar_linea() {
  # Cierra la línea de progreso pendiente: borra su contenido y avanza de línea.
  (( LINEA_PROGRESO == 0 )) && return 0
  LINEA_PROGRESO=0
  if _tty; then printf '\033[2K\r'; else printf '\n'; fi
}
 
_xf_user() {
  # Con root degrada al usuario; sin root (modo --marca-usuario) ejecuta directo.
  # Exporta DBUS_SESSION_BUS_ADDRESS del usuario (xfce4-panel --add y xfconf
  # necesitan hablar con el bus de sesión del usuario real; sin esto, las
  # operaciones se desvían a un xfconfd fantasma y no afectan al panel visible).
  local uid dbus
  uid=$(getent passwd "$USUARIO_REAL" 2>/dev/null | cut -d: -f3)
  uid=${uid:-$(id -u "$USUARIO_REAL" 2>/dev/null)}
  if [[ -z "$uid" || "$uid" == 0 ]]; then
    aviso "No se pudo resolver el uid real de $USUARIO_REAL"
    return 1
  fi
  dbus="unix:path=/run/user/$uid/bus"
  if (( EUID == 0 )); then
    sudo -u "$USUARIO_REAL" env DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$HOME_REAL/.Xauthority" \
      DBUS_SESSION_BUS_ADDRESS="$dbus" "$@"
  else
    env DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$HOME_REAL/.Xauthority" \
      DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-$dbus}" "$@"
  fi
}

_arrancar_panel_usuario() {
  # Apaga y relanza el panel del usuario real con DBUS de sesión correcto.
  _xf_user xfce4-panel -q >/dev/null 2>&1 || true
  sleep 1
  local uid dbus
  uid=$(id -u "$USUARIO_REAL" 2>/dev/null)
  dbus="unix:path=/run/user/${uid:-1000}/bus"
  # `</dev/null` + cierre explícito de fds heredables: el wrapper `sudo -u …`
  # queda vivo esperando al panel; si hereda un fd de lock del padre, el lock
  # queda tomado eternamente aunque el script termine (bug real, corregido
  # además en bloquear_instancia con flock+FD_CLOEXEC; esto es defensa extra).
  if (( EUID == 0 )); then
    setsid sudo -u "$USUARIO_REAL" env DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$HOME_REAL/.Xauthority" \
      DBUS_SESSION_BUS_ADDRESS="$dbus" nohup xfce4-panel </dev/null >/dev/null 2>&1 200>&- &
  else
    setsid env DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$HOME_REAL/.Xauthority" \
      DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-$dbus}" nohup xfce4-panel </dev/null >/dev/null 2>&1 200>&- &
  fi
  disown 2>/dev/null || true
  sleep 1
}

_dueno() {  # restaurar dueño de archivos del usuario (no hace nada si ya se ejecuta como él)
  (( EUID == 0 )) && chown -R "$USUARIO_REAL":"$(id -gn "$USUARIO_REAL")" "$@"
  return 0
}

_xf_set() {  # $1 canal · $2 prop · $3 tipo · $4 valor
  _xf_user xfconf-query -c "$1" -p "$2" -n -t "$3" -s "$4" >/dev/null
}

_escribir() {  # $1 destino · resto: líneas del archivo
  local d="$1"; shift
  mkdir -p "${d%/*}"
  printf '%s\n' "$@" > "$d"
}

_ya_escrito() {  # $1 destino · resto: contenido esperado
  local d="$1"; shift
  [[ -f "$d" ]] && diff <(printf '%s\n' "$@") "$d" >/dev/null
}

_instalado() { [[ -s "$1" ]]; }  # $1 archivo persistente con contenido

# Resuelve el ejecutable de Chromium/Chrome disponible en el sistema, en orden
# de preferencia. Fuente única de verdad (DRY): la usan el symlink del MCP de
# chrome-devtools (línea ~1414), el parche de UserConfig.json de Burp Suite y
# cualquier consumidor futuro. Imprime la ruta por stdout; vacío si no hay.
_resolver_chromium_bin() {
  local c
  for c in /opt/google/chrome/chrome /usr/lib/chromium/chromium \
           /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome; do
    [[ -x "$c" ]] && { printf '%s\n' "$c"; return 0; }
  done
  command -v chromium chromium-browser google-chrome 2>/dev/null | head -n1
}

# Escribe un archivo del usuario COMO USUARIO (nunca root+chown): pre-crea el
# directorio padre como usuario y restaura dueño al final. Política: todo lo
# que vive bajo $HOME_REAL debe ser editable por el usuario sin sudo; los
# archivos creados por root heredan umask/permisos inconsistentes y el
# operador no puede modificarlos después (bug real con terminalrc/.XCompose).
# Excepción /etc/skel: el mkdir como usuario puede fail (EACCES) y NO se
# chown-ea (los prototipos del skel son root:root por convención).
_escribir_usuario() {  # $1 destino · resto: líneas del archivo
  local d="$1"
  _como_usuario bash -c "mkdir -p '${d%/*}'" 2>/dev/null || true
  _escribir "$@"
  [[ "$d" == /etc/skel/* ]] || _dueno "$d"
}

# Symlink de un binario del usuario en ~/.local/bin (idempotente + dueño
# correcto). Centraliza el patrón "mkdir dir como usuario + ln -sf + _dueno"
# que estaba repetido en x8/commix/gospider/GoLinkFinder con un bash -c
# inline; cada copia era un lugar donde root podía crear el symlink con
# dueño incorrecto antes del _dueno final.
_linkear_bin_usuario() {  # $1 src · $2 nombre_en_~/.local/bin
  _como_usuario bash -c "mkdir -p '$HOME_REAL/.local/bin' && ln -sf '$1' '$HOME_REAL/.local/bin/$2'"
}

# Descarga un asset de un repo de GitHub si no está presente.
# $1 destino · $2 marker-existe (regex si empieza por 're:', literal si vacío)
# $3 ruta-relativa en el repo (ej. 'enumerathor.py')
# $4 descripción · [$5 repo='DragonJAR/Scripts'] · [$6 branch='master']
# [$7 kind: auto|python|bash|bulk — auto se infiere por extensión]
# marker vacío ('') = solo verifica que el archivo exista y no esté vacío.
# La validación es por tipo: antes TODO se validaba como python3
# (shebang exacto + py_compile), con lo que .jpg/.xml/.sh NUNCA podían
# descargarse (fallo silencioso-recurrente en cada corrida).
_descargar_script() {
  local destino="$1" marker="$2" rel="$3" desc="$4"
  local repo="${5:-DragonJAR/Scripts}" branch="${6:-master}"
  local kind="${7:-auto}"
  if [[ "$kind" == auto ]]; then
    case "$destino" in
      *.py) kind=python ;;
      *.sh) kind=bash ;;
      *)    kind=bulk ;;
    esac
  fi
  local ok=0
  if [[ -s "$destino" ]]; then
    if [[ "$marker" == re:* ]]; then
      grep -q "${marker#re:}" "$destino" 2>/dev/null && ok=1
    else
      [[ -f "$destino" && -s "$destino" ]] && ok=1
    fi
  fi
  if (( ok )); then
    info "$desc ya está en $destino"
    return 0
  fi
  # Validación según tipo (se evalúa en el bash -c hijo; $marker viaja
  # escapado por entorno para no romper el entrecomillado si trae '/').
  local val_py='python3 -m py_compile "$DL_NEW"'
  local val_sh='bash -n "$DL_NEW"'
  [[ "$marker" == re:* ]] && {
    val_py+=" && grep -q \"${marker#re:}\" \"\$DL_NEW\""
    val_sh+=" && grep -q \"${marker#re:}\" \"\$DL_NEW\""
  }
  local val_bulk='[[ -s "$DL_NEW" ]]'
  [[ "$marker" == re:* ]] && val_bulk+=" && grep -q \"${marker#re:}\" \"\$DL_NEW\""
  local val_cmd="$val_bulk"
  case "$kind" in
    python) val_cmd="$val_py" ;;
    bash)   val_cmd="$val_sh" ;;
  esac
  ejecutar "Descargando $desc" \
    _como_usuario env HOME="$HOME_REAL" DL_NEW="$destino.new" \
      DL_DEST="$destino" DL_URL="https://raw.githubusercontent.com/${repo}/${branch}/${rel}" \
      DL_VAL="$val_cmd" bash -c '
      set -u
      mkdir -p "${DL_DEST%/*}" &&
      rm -f "$DL_NEW" &&
      curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --max-time 60 -o "$DL_NEW" "$DL_URL" &&
      sed -i "s/\r$//" "$DL_NEW" &&
      bash -c "$DL_VAL" &&
      mv "$DL_NEW" "$DL_DEST" &&
      case "$DL_DEST" in
        *.sh|*.py) chmod +x "$DL_DEST" ;;
      esac'
}

# Clona un repo git en $1 (o lo sincroniza con la política adecuada si ya
# existe). DRY: reemplaza los ~9 bloques `mkdir && git clone --depth 1`
# dispersos. Política por tipo:
#   tool        : código de herramienta (ghauri/x8/commix/sippts/cupp/npo).
#                 `pull --ff-only` (rechaza divergencias silenciosamente).
#   feed        : contenido mutable externo (nuclei-templates, ~150MB).
#                 `fetch + reset --hard origin/HEAD` — el operador quiere el
#                 contenido actualizado, no un merge que pueda fallar cuando
#                 el upstream tiene historial no-lineal (causa real del
#                 "nuclei-templates siempre falla en otra máquina": un
#                 --ff-only contra un repo con force-push diverge y el helper
#                 viejo tragaba el error diciendo "se conserva la copia local"
#                 mientras dejaba templates obsoletos).
#   disposable  : repo que se re-clona limpio (OneForAll: si quedó parcial se
#                 borra y se vuelve a clonar).
# Corrige: `rm -rf <dir> && git clone ... || true` (éxito falso rc=128
# enmascarado), pull silencioso sin red, ausencia de git → aviso claro.
_git_clonar() {
  local dest="$1" url="$2" desc="$3" kind="${4:-tool}"
  local git_ok=0
  command -v git >/dev/null 2>&1 || {
    aviso "git no está disponible: no se puede sincronizar $desc; se omite"
    return 1
  }
  if [[ -d "$dest/.git" ]]; then
    # Repo existente: sincronizar según política.
    case "$kind" in
      feed)
        # Fetch + reset hard contra origin/HEAD: trae TODOS los refs (incluidos
        # tags nuevos) y descarta cualquier local divergente. --depth 1 en el
        # clone inicial no impide el fetch completo posterior.
        if _como_usuario env HOME="$HOME_REAL" bash -c "
            cd '$dest' &&
            git fetch --tags --prune --prune-tags --force origin '+refs/heads/*:refs/remotes/origin/*' 2>>'$REGISTRO' &&
            git reset --hard origin/HEAD 2>>'$REGISTRO'
          "; then
          info "$desc sincronizado (feed · fetch+reset)"
        else
          aviso "$desc no se pudo sincronizar (¿sin conexión?): se conserva la copia local"
        fi
        ;;
      disposable)
        # Re-clonar limpio siempre.
        ejecutar "Re-clonando $desc (disposable)" \
          _como_usuario bash -c "rm -rf '$dest' && git clone -q --depth 1 '$url' '$dest'" \
          || git_ok=1
        ;;
      *)
        # tool: pull ff-only.
        if _como_usuario bash -c "cd '$dest' && git pull -q --ff-only" >>"$REGISTRO" 2>&1; then
          info "$desc ya estaba clonado, actualizado"
        else
          aviso "$desc no se pudo actualizar (¿sin conexión?): se conserva la copia local"
        fi
        ;;
    esac
    return 0
  fi
  # No existe: clonar desde cero (limpieza previa si quedó algo).
  if [[ -e "$dest" ]]; then
    ejecutar "Limpiando $desc parcial/incompleto" bash -c "rm -rf '$dest'"
  fi
  ejecutar "Clonando $desc" \
    _como_usuario bash -c "mkdir -p '${dest%/*}' && git clone -q --depth 1 '$url' '$dest'" \
    || git_ok=1
  return "$git_ok"
}

# Asegura una línea `export PATH="<ruta>:$PATH"` en el rc del usuario.
# DRY: reemplaza los 4 bloques manuales (opencode/.local/gopath) que además
# eran inconsistentes (unos exigían -f, otros decían crear el archivo).
# Crea el archivo si no existe; idempotente por grep -qF. Bilingüe: escribe
# en ~/.bashrc Y ~/.zshrc (Kali usa zsh como login shell por defecto desde
# 2020.4; sin esto ninguna ruta PATH del script llega a las consolas zsh).
_asegurar_path_bashrc() {
  local patron ruta etiqueta f
  if (( $# >= 4 )); then
    patron="$2"; ruta="$3"; etiqueta="$4"
  else
    patron="$1"; ruta="$2"; etiqueta="$3"
  fi
  for f in "$HOME_REAL/.bashrc" "$HOME_REAL/.zshrc"; do
    if [[ ! -f "$f" ]]; then
      touch "$f" && _dueno "$f"
    fi
    grep -qF "$patron" "$f" 2>/dev/null && continue
    printf '\n# KALI-DSIO: %s\nexport PATH="%s:$PATH"\n' "$etiqueta" "$ruta" >> "$f"
    _dueno "$f"
  done
}

# Asegura que un paquete apt esté instalado (root); idempotente y con aviso.
# $1 binario · $2 paquete-apt (si difiere del binario) · $3 comando de versión
_asegurar_apt_pkg() {
  # Gate DRY de apt update (un solo lugar lo decide: listas recientes? no → update).
  _asegurar_apt_update
  local bin="$1" pkg="${2:-$1}" vcmd="${3:-$1 --version}"
  local instalado=0
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    instalado=1
  elif [[ "$pkg" == "$bin" ]] && command -v "$bin" >/dev/null 2>&1; then
    instalado=1
  fi
  if (( instalado )); then
    local ver
    ver=$(bash -c "$vcmd" 2>&1 | head -1)
    info "$pkg ya está instalado (${ver:-ok})"
    return 0
  fi
  if (( EUID == 0 )); then
    ejecutar "Instalando $pkg (apt)" apt-get install -y -qq --no-install-recommends "$pkg"
  else
    aviso "$pkg no está instalado y requiere root: corré 'sudo $0 --herramientas' (o sudo $0) si lo necesitás."
  fi
}

# Ejecuta un comando como $USUARIO_REAL. Si ya somos ese usuario corre directo
# (evita prompts de password en modo --herramientas sin root ni sudo cacheado).
_como_usuario() {
  # NOTA: nunca llamar a _como_usuario dentro de sí misma (recursión infinita
  # con EUID==0 → desbordamiento de pila). La degradación a usuario es directa.
  # El helper NO acepta opciones (p. ej. `-H` de sudo): ya fija HOME al del
  # usuario objetivo en ambas ramas, y un flag suelto caería sobre `env`
  # (bug real: `_como_usuario -H bash …` → `env: -H: No such file`, rc=127).
  case "${1:-}" in
    -*) printf 'ERROR _como_usuario: opción %q no soportada (el helper ya fija HOME; no pasar flags de sudo)\n' "$1" >&2
        return 2 ;;
  esac
  if (( EUID == 0 )) && [[ "$USUARIO_REAL" != "root" ]] && [[ -n "$USUARIO_REAL" ]]; then
    sudo -u "$USUARIO_REAL" env HOME="$HOME_REAL" "$@"
  else
    env HOME="$HOME_REAL" "$@"
  fi
}

# Gates de recursos (fail-fast ANTES de descargas/compilaciones pesadas, para
# no abortar a mitad de corrida con estado parcial). Leen KDSIO_* de
# _detectar_sistema. Retornan 0 = continuar, 1 = saltar el bloque llamador.
# Sin red (KDSIO_RED=caida) todo gate que implica descarga también corta.
_gate_disco() {  # $1 MB-libres-mínimos · $2 descripción del bloque
  local min_mb="$1" desc="$2"
  if (( KDSIO_DISCO_MB < min_mb )); then
    aviso "Sin espacio para $desc: libres ${KDSIO_DISCO_MB}MB < ${min_mb}MB requeridos; se omite"
    return 1
  fi
  return 0
}
_gate_ram() {  # $1 MB-mínimos · $2 descripción del bloque
  local min_mb="$1" desc="$2"
  if (( KDSIO_MEM_MB > 0 && KDSIO_MEM_MB < min_mb )); then
    aviso "RAM insuficiente para $desc: ${KDSIO_MEM_MB}MB < ${min_mb}MB; se omite (riesgo OOM)"
    return 1
  fi
  return 0
}
_gate_red() {  # $1 descripción del bloque
  local desc="$1"
  if [[ "$KDSIO_RED" != "ok" ]]; then
    aviso "Sin red (DNS kali.org falla): $desc requiere descarga; se omite"
    return 1
  fi
  return 0
}

# apt-get update solo si hace falta (listas vacías o muy antiguas). Tras
# fase_cierre (rm -rf /var/lib/apt/lists/*) o tras imagen recién clonada,
# la siguiente corrida con --herramientas fallaría "Unable to locate package"
# sin este gate. Un único `apt-get update` por corrida, centralizado aquí.
APT_UPDATE_HECHO=0
_asegurar_apt_update() {
  (( EUID == 0 )) || return 0
  (( APT_UPDATE_HECHO )) && return 0          # idempotente por corrida
  [[ "$KDSIO_RED" == "ok" ]] || return 0
  # Chequeo barato: si hay algún archivo *.deb.list reciente (mtime < 1h), apt
  # está al día. Sin lista reciente → update silencioso.
  if find /var/lib/apt/lists -maxdepth 1 -name '*.deb.list' -mmin -60 2>/dev/null | grep -q .; then
    APT_UPDATE_HECHO=1
    return 0
  fi
  info "apt: listas ausentes/anticuadas → apt-get update (una vez por corrida)"
  if apt-get update -qq >>"$REGISTRO" 2>&1; then
    APT_UPDATE_HECHO=1
  else
    aviso "apt-get update falló; las próximas instalaciones de paquetes pueden fallar — corré 'sudo apt-get update' a mano"
  fi
}

# Purga copias user-site (~/.local) que eclipsan módulos que apt provee
# compilados contra la Python del sistema. Caso real: un sqlalchemy 1.3 viejo
# en ~/.local sombreaba al 2.0 del apt y rompía NetExec con
# "ImportError: cannot import name 'IllegalStateChangeError'".
# Regla: si el módulo importa desde ~/.local, la copia de usuario se elimina
# y Python resuelve contra la del sistema (apt).
_purgar_sombra_pip() {
  local mod="$1" ruta=""
  ruta=$(_como_usuario python3 -c "import $mod; print($mod.__file__)" 2>/dev/null || true)
  if [[ "$ruta" == *"/.local/"* ]]; then
    ejecutar "Purgando copia user-site de '$mod' (eclipsa la del sistema y rompe herramientas del apt)" \
      _como_usuario python3 -m pip uninstall -y --break-system-packages "$mod"
  else
    info "'$mod' resuelve correctamente contra el sistema ($ruta)"
  fi
}

# Repara el DNS del sistema si está roto (resolutor NAT de VMware corrompe
# respuestas DNSSEC: devuelve firmas RRSIG "10 8 …=" en vez de registros A).
# Estrategia: probar resolviendo kali.org → si falla, cambiar a 1.1.1.1/8.8.8.8
# vía NetworkManager (persistente). Fallback: escribir /etc/resolv.conf.
_reparar_dns() {
  local out
  # ahostsv4: getent hosts devuelve IPv6 primero en hosts con v6, y el test
  # IPv4-only reportaría falso negativo (bug detectado en validación).
  if out=$(timeout 8 getent ahostsv4 kali.org 2>/dev/null | head -1) \
     && [[ "$out" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    info "DNS del sistema funciona ($(grep -m1 nameserver /etc/resolv.conf | awk '{print $2}'))"
    return 0
  fi
  if (( EUID == 0 )) && command -v nmcli >/dev/null 2>&1; then
    local con_line con dev
    # nmcli -t escapa ':' como '\:' en los nombres: el cut -d: -f1 clásico
    # truncaba conexiones con ':' en el nombre. Se des-escapa antes de cortar.
    con_line=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | head -1)
    if [[ -n "$con_line" ]]; then
      dev="${con_line##*:}"
      con=$(sed 's/\\:/\x00/g; s/:.*//; s/\x00/:/g' <<<"$con_line")
      # La conexión viaja por entorno (KDSIO_CON), no interpolada en el
      # string: un nombre con comilla simple era inyección de shell.
      # `device reapply` (no `con up`): re-aplica DNS SIN derribar la
      # interfaz — `con up` cortaba la sesión SSH del operador a mitad de
      # corrida si administraba la VM remotamente (bug real reportado).
      ejecutar "DNS roto: aplicando 1.1.1.1/8.8.8.8 en '$con' (reapply en $dev)" env KDSIO_CON="$con" KDSIO_DEV="$dev" bash -c \
        'nmcli con mod "$KDSIO_CON" ipv4.dns "1.1.1.1 8.8.8.8" ipv4.ignore-auto-dns yes && { [[ -n "$KDSIO_DEV" ]] && nmcli dev reapply "$KDSIO_DEV" 2>/dev/null; } || nmcli con up "$KDSIO_CON"'
    else
      ejecutar "DNS roto: escribiendo resolv.conf (sin NetworkManager)" _escribir \
        /etc/resolv.conf "nameserver 1.1.1.1" "nameserver 8.8.8.8"
    fi
  elif (( EUID == 0 )); then
    ejecutar "DNS roto: escribiendo resolv.conf (sin nmcli)" _escribir \
      /etc/resolv.conf "nameserver 1.1.1.1" "nameserver 8.8.8.8"
  else
    aviso "DNS del sistema está roto y requiere root para repararlo"
    aviso "Corré: sudo nmcli con mod <conexión> ipv4.dns '1.1.1.1 8.8.8.8' ipv4.ignore-auto-dns yes && sudo nmcli con up <conexión>"
    return 1
  fi
  # Re-verificar (ahostsv4: mismo fix que arriba)
  if out=$(timeout 8 getent ahostsv4 kali.org 2>/dev/null | head -1) \
     && [[ "$out" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    info "DNS reparado: kali.org resuelve a $(awk '{print $1}' <<<"$out")"
    return 0
  fi
  aviso "DNS sigue sin funcionar tras el fix: revisá la conectividad de la VM"
  return 1
}

# Gate de arranque: sin estas herramientas el script no puede funcionar.
# Si falta alguna y somos root, la instala; si no somos root, aborta claro.
# Además: re-fresca la detección canónica (KDSIO_RED puede cambiar tras
# reparar DNS) y reporta el resumen de sistema detectado una sola vez.
_preflight() {
  local -a esenciales=(curl git unzip file convert python3)
  local -a paquetes=(curl git unzip file imagemagick python3)
  local -a faltan=()
  local i bin
  for i in "${!esenciales[@]}"; do
    bin="${esenciales[$i]}"
    command -v "$bin" >/dev/null 2>&1 || faltan+=("${paquetes[$i]}")
  done
  # El DNS se repara SIEMPRE (antes solo cuando faltaban paquetes; en el
  # camino limpio se saltaba y fase_actualizacion fallaba igual después).
  _reparar_dns || true
  # Re-detección: KDSIO_RED/KDSIO_DISCO_MB pueden haber cambiado tras el
  # fix de DNS y los apt del propio preflight.
  KDSIO_ARCH=""; _detectar_sistema
  info "Sistema detectado: arch=$KDSIO_ARCH (raw=$KDSIO_ARCHRAW) · virt=$KDSIO_VIRT · de=$KDSIO_DE · sesión=$KDSIO_SESION · RAM=${KDSIO_MEM_MB}MB · CPU=$KDSIO_NCPU · disco-libre=${KDSIO_DISCO_MB}MB · red=$KDSIO_RED"
  if (( ${#faltan[@]} == 0 )); then
    info "Prerrequisitos verificados (curl, git, unzip, file, convert, python3)"
    return 0
  fi
  if (( EUID == 0 )); then
    ejecutar "Instalando prerrequisitos faltantes (${faltan[*]})" \
      apt-get install -y -qq --no-install-recommends "${faltan[@]}"
    local aun=()
    for i in "${!esenciales[@]}"; do
      bin="${esenciales[$i]}"
      command -v "$bin" >/dev/null 2>&1 || aun+=("${paquetes[$i]}")
    done
    if (( ${#aun[@]} > 0 )); then
      aviso "Prerrequisitos aún ausentes tras instalar: ${aun[*]}"
      return 1
    fi
    info "Prerrequisitos instalados correctamente"
  else
    aviso "Faltan prerrequisitos esenciales: ${faltan[*]}"
    aviso "Corré 'sudo $0' una vez para instalarlos, o instalalos a mano con:"
    printf '  %ssudo apt-get install -y %s%s\n' "$B" "${faltan[*]}" "$R"
    exit 1
  fi
}

# Borra archivos de historial (bash/zsh) de root y del usuario real, y deja
# un .bash_history vacío en cada home (permisos 600, dueño correcto).
_limpiar_historiales() {
  local h f
  for h in /root "$HOME_REAL"; do
    for f in .bash_history .zsh_history .zhistory; do
      [[ -e "$h/$f" ]] && rm -f -- "$h/$f"
    done
    touch "$h/.bash_history"
    chmod 600 "$h/.bash_history"
    if [[ "$h" == /root ]]; then
      chown root:root "$h/.bash_history"
    else
      chown "$USUARIO_REAL":"$(id -gn "$USUARIO_REAL")" "$h/.bash_history"
    fi
  done
  rm -f -- /root/.viminfo
}

_fuentes_instaladas() {
  local f
  for f in PlusJakartaSans.ttf Montserrat.ttf IBMPlexMono-Regular.ttf; do
    _instalado "$DIR_FUENTES/$f" || return 1
  done
}

# Nerd Fonts renombró el parche de IBM Plex Mono a "Blex Mono" (v3+):
# se aceptan ambos nombres y variantes (Mono/regular) por robustez ante releases.
_plex_nerd_instalada() {
  _instalado "$DIR_FUENTES/BlexMonoNerdFontMono-Regular.ttf" \
    || _instalado "$DIR_FUENTES/BlexMonoNerdFont-Regular.ttf" \
    || _instalado "$DIR_FUENTES/IBMPlexMonoNerdFont-Regular.ttf"
}

_instalar_plex_nerd() {
  local -a ttf=() f
  unzip -oq "$DIR_TMP_MARCA/plexnerd.zip" -d "$DIR_TMP_MARCA/nf" || return 1
  for f in "$DIR_TMP_MARCA"/nf/*NerdFont*.ttf; do
    [[ -f $f ]] || continue
    case "${f##*/}" in
      *NerdFontMono-Regular.ttf|*NerdFontMono-Bold.ttf|*NerdFont-Regular.ttf|*NerdFont-Bold.ttf)
        ttf+=("$f") ;;
    esac
  done
  (( ${#ttf[@]} > 0 )) || return 1
  mkdir -p "$DIR_FUENTES"   # defensivo: si las fuentes de marca fallaron
                            # (rama que no crea $DIR_FUENTES), el Nerd Font
                            # se instala igual.
  install -m644 "${ttf[@]}" "$DIR_FUENTES/"
  fc-cache -f >/dev/null 2>&1
}
 
# Wrapper retrocompatible: SESION_GRAFICA se sigue usando en 4 sitios legacy.
# Fuente única es KDSIO_SESION (de _detectar_sistema). Mantener esta función
# vacía + la asignación global evita tocar todos los call-sites; se reasigna
# aquí para que cualquier lectura posterior vea el valor canónico.
detectar_sesion_grafica() {
  case "${KDSIO_SESION:-headless}" in
    x11|wayland) SESION_GRAFICA=1 ;;
    *)           SESION_GRAFICA=0 ;;
  esac
}
 
bloquear_instancia() {
  # Lock SIN herencia de fd: re-ejecuta el script bajo flock(1) de util-linux
  # CON `--close`, que cierra el fd del lock en el proceso hijo antes del exec.
  # Sin --close, el fd se hereda al hijo y cualquier superviviente (sudo/setsid/
  # nohup de xfce4-panel, daemons) mantiene el lock ETERNAMENTE tras terminar
  # el script (bug real). Verificado: `flock --close lock bash -c …` → el hijo
  # ve 0 fds del lock en /proc/$$/fd. El patrón anterior (`exec 200>lock;
  # flock -n 200`) sí heredaba y producía "Ya existe otra ejecución" para siempre.
  command -v flock >/dev/null 2>&1 || return 0
  [[ "${KDSIO_LOCK_TOMADO:-}" == "1" ]] && return 0
  local lock=/tmp/KALI-DSIO.sh.lock
  (( EUID != 0 )) && lock="/tmp/KALI-DSIO.$USUARIO_REAL.lock"
  export KDSIO_LOCK_TOMADO=1
  # `-E 200`: el lock OCUPADO tiene rc=200 (no 1), distinto del rc del
  # HIJO (que propaga al final). Captura DIRECTA de rc — dentro de un
  # `if ! cmd; then`, `$?` es de la condición invertida y siempre sería 0
  # (misma clase de bug que gvm_ok=0; (( $? == 0 ))).
  flock -n --close -E 200 "$lock" "$0" "$@"
  flock_rc=$?
  if (( flock_rc == 200 )); then
    _cerrar_linea
    printf '  %sYa existe otra ejecución de KALI-DSIO en curso.%s\n' "$ROJO$B" "$R"
    if command -v fuser >/dev/null 2>&1; then
      local holders
      holders=$(fuser -v "$lock" 2>&1 | tr -s ' \n' '  ')
      [[ -n "${holders// /}" ]] && printf '  %sPortador del lock:%s %s\n' "$GRIS" "$R" "$holders"
    fi
    printf '  %sSi es un residuo (sin corrida viva): sudo rm -f %s%s\n' "$GRIS" "$lock" "$R"
    exit 1
  fi
  exit "$flock_rc"
}

verificar_sistema() {
  if [[ -r /etc/os-release ]] && grep -q '^ID=kali' /etc/os-release; then
    return 0
  fi
  if (( SIMULAR )); then
    aviso "Sistema no-Kali (simulación): en modo real este script se detiene aquí"
    return 0
  fi
  printf '  %sEste script es exclusivo de Kali Linux (ID=kali en /etc/os-release).%s\n' "$ROJO$B" "$R"
  exit 1
}
 
# shellcheck disable=SC1003
_ARTE_DRAGONJAR=' _____  _____            _____  ____  _   _      _         _____  
|  __ \|  __ \     /\   / ____|/ __ \| \ | |    | |  /\   |  __ \
| |  | | |__) |   /  \ | |  __| |  | |  \| |    | | /  \  | |__) |
| |  | |  _  /   / /\ \| | |_ | |  | | . ` |_   | |/ /\ \ |  _  /
| |__| | | \ \  / ____ \ |__| | |__| | |\  | |__| / ____ \| | \ \
|_____/|_|  \_\/_/    \_\_____|\____/|_| \_|\____/_/    \_\_|  \_\'

encabezado() {
  # DRY: usa el mismo arte DRAGONJAR que /etc/motd y /etc/issue.
  printf '%s\n' "${ROJO}${B}${_ARTE_DRAGONJAR}${R}"
  printf '%s\n  KALI-DSIO v%s · Kali Linux para distribución · VM o física\n%s' "$B" "$VERSION" "$R"
}

separador() { _cerrar_linea; printf '%s\n' "${GRIS}  ├──────────────────────────────────────────────${R}"; }
info()      { _cerrar_linea; printf '  %s\n' "${AZUL}${B}•${R} $*"; }
aviso()     { _cerrar_linea; printf '  %s\n' "${AMARILLO}${B}⚠${R} ${AMARILLO}$*${R}"; }
titulo_fase(){ _cerrar_linea; printf '\n'; separador; printf '  %s\n' "${ROJO}${B}▌ $*${R}"; }

# Contador global [hechos/total] con barra █: feedback de avance en una sola
# línea. Se dibuja al terminar cada paso y _cerrar_linea la limpia antes de
# cualquier mensaje, de modo que nunca se mezcla con el texto de flujo.
barra() {
  local hechos=$PASO_ACTUAL total=$TOTAL_PASOS ancho=20
  (( total == 0 )) && return
  _tty || return
  local llenos=$(( hechos * ancho / total ))
  local color="$VERDE"
  (( PASOS_FALLIDOS > 0 )) && color="$AMARILLO"
  local bloques="" i
  for (( i = 0; i < llenos; i++ )); do bloques+="█"; done
  printf '\r  %s%s%s %s[%d/%d]%s ' \
    "$color" "$bloques" \
    "$R" "$B" "$hechos" "$total" "$R"
  LINEA_PROGRESO=1
}

_marcar_paso() {  # $1 descripción — imprime el encabezado del paso sin salto de línea
  _cerrar_linea
  PASO_ACTUAL=$((PASO_ACTUAL + 1)); TOTAL_PASOS=$((TOTAL_PASOS + 1))
  printf '  %s[%d/%d]%s %s ' \
    "$B" "$PASO_ACTUAL" "$TOTAL_PASOS" "$R" "$1"
}

ejecutar() {
  local desc="$1"; shift
  _marcar_paso "$desc"
  if [[ $SIMULAR -eq 1 ]]; then
    printf '%s[simulado]%s\n' "$GRIS" "$R"; SIMULADOS=$((SIMULADOS + 1)); barra; return 0
  fi
  {
    printf '\n──────[%s] %s\n' "$(date +%H:%M:%S)" "$desc"
    "$@"
  } >>"$REGISTRO" 2>&1
  local rc=$?
  if (( rc == 0 )); then
    printf '%s✓%s\n' "$VERDE$B" "$R"; PASOS_OK=$((PASOS_OK + 1))
  else
    printf '%s✗ (rc=%d, ver %s)%s\n' "$ROJO$B" "$rc" "$REGISTRO" "$R"
    PASOS_FALLIDOS=$((PASOS_FALLIDOS + 1)); NOMBRES_FALLIDOS+=("$desc")
  fi
  barra
  # Propagar el rc real: sin esto `ejecutar ... || true` es código muerto y
  # cualquier `(( $? == 0 ))` posterior siempre es verdadero (éxito falso).
  return "$rc"
}

paso_simulado() {
  _marcar_paso "$1"; printf '%s[simulado]%s\n' "$GRIS" "$R"
  SIMULADOS=$((SIMULADOS + 1)); barra
}
 
confirmar() {
  (( ASUMIR_SI )) && return 0
  local respuesta=""
  _cerrar_linea
  # El prompt va por stdout: read -p lo escribe a stderr y el 2>/dev/null
  # de abajo lo silenciaba (espera invisible para el usuario)
  printf '  %s¿Continuar? (s/si = seguir · Enter o n = cancelar): %s' "$B" "$R"
  if ! read -t 120 -r respuesta </dev/tty 2>/dev/null; then
    printf '\n'
    aviso "Sin respuesta en 120 s: se interpreta como No"
    return 1
  fi
  printf '\n'
  [[ "$respuesta" =~ ^[sS][iIíÍ]?$ ]]
}
 
fase_cursor() {
  titulo_fase "Fase 1/9 · Cursor del mouse (vmwgfx)"
  if [[ "$VIRTUALIZACION" != "vmware" ]]; then
    info "No es VMware ($ETIQUETA_VIRT): se omite el fix de cursor"
    return 0
  fi
  local conf=/etc/X11/xorg.conf.d/20-vmware-cursor.conf
  if _ya_escrito "$conf" \
     'Section "Device"' '    Identifier "VMware SVGA"' '    Driver "modesetting"' '    Option "SWcursor" "true"' 'EndSection'; then
    info "El fix de cursor ya está aplicado"
    return 0
  fi
  ejecutar "Escribiendo $conf (SWcursor)" _escribir "$conf" \
    'Section "Device"' '    Identifier "VMware SVGA"' '    Driver "modesetting"' '    Option "SWcursor" "true"' 'EndSection'
}
 
fase_idioma() {
  titulo_fase "Fase 2/9 · Locale del sistema"
  if locale -a 2>/dev/null | grep -qi 'en_US.utf8'; then
    info "en_US.UTF-8 ya está generado"
    return 0
  fi
  ejecutar "Generando en_US.UTF-8" bash -c 'grep -q "^en_US.UTF-8 UTF-8" /etc/locale.gen || echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen; locale-gen'
  ejecutar "Aplicando idioma por defecto" update-locale LANG=en_US.UTF-8
}
 
fase_teclado() {
  titulo_fase "Fase 3/9 · Teclado español latinoamericano"
  ejecutar "Configuración gráfica (latam/pc105)" _escribir /etc/X11/xorg.conf.d/00-keyboard.conf \
    'Section "InputClass"' '    Identifier "system-keyboard"' '    MatchIsKeyboard "on"' \
    '    Option "XkbModel" "pc105"' '    Option "XkbLayout" "latam"' 'EndSection'
  ejecutar "Configuración de consola" _escribir /etc/default/keyboard \
    'XKBMODEL="pc105"' 'XKBLAYOUT="latam"' 'XKBVARIANT=""' 'XKBOPTIONS=""'
  if (( SESION_GRAFICA )); then
    ejecutar "Layout en sesión activa (xfconf)" _xf_teclado
  else
    info "Sin sesión gráfica activa: el layout se aplicará al iniciar sesión"
  fi
}

_xf_teclado() {
  _xf_user setxkbmap latam
  _xf_set keyboard-layout /Default/XkbLayout string latam
  _xf_set keyboard-layout /Default/XkbModel string pc105
}
 
fase_actualizacion() {
  titulo_fase "Fase 4/9 · Actualización del sistema"
  if [[ $SIMULAR -eq 1 ]]; then
    paso_simulado "Reparando dpkg interrumpido"
    paso_simulado "Verificando DNS (auto-reparación si está roto)"
    paso_simulado "Actualizar paquetes (3 reintentos)"
    paso_simulado "Autolimpieza de paquetes"
    return 0
  fi
  ejecutar "Reparando dpkg interrumpido" bash -c 'dpkg --configure -a'
  # El DNS NAT de VMware corrompe respuestas DNSSEC y rompe apt/pip/go/git:
  # re-verificar justo antes de la descarga masiva (preflight ya lo intentó).
  ejecutar "Verificando y reparando DNS si está roto" _reparar_dns || true
  info "La actualización completa puede tardar varios minutos; el detalle va al registro"
  local intento logrado=0
  for intento in 1 2 3; do
    info "Intento de actualización $intento/3..."
    if apt-get update -qq >>"$REGISTRO" 2>&1 \
       && apt-get -y --fix-broken -o Acquire::Retries=5 \
            -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold install >>"$REGISTRO" 2>&1 \
       && apt-get -y -o Acquire::Retries=5 \
            -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold full-upgrade >>"$REGISTRO" 2>&1; then
      logrado=1; break
    fi
    sleep 10
  done
  PASO_ACTUAL=$((PASO_ACTUAL + 1)); TOTAL_PASOS=$((TOTAL_PASOS + 1)); barra
  if (( logrado )); then
    printf '  %s✓%s\n' "$VERDE$B" "$R"; PASOS_OK=$((PASOS_OK + 1))
  else
    printf '  %s✗ tras 3 intentos%s\n' "$ROJO$B" "$R"
    PASOS_FALLIDOS=$((PASOS_FALLIDOS + 1)); NOMBRES_FALLIDOS+=("apt full-upgrade")
  fi
  printf '\n'
  ejecutar "Autolimpieza de paquetes" bash -c 'apt-get autoremove -y -qq >/dev/null; apt-get clean'
}

fase_herramientas() {
  titulo_fase "Fase 5/9 · Herramientas de invitado"
  local -a pkgs=()
  case "$VIRTUALIZACION" in
    vmware)    pkgs=(open-vm-tools open-vm-tools-desktop) ;;
    kvm|qemu)  pkgs=(qemu-guest-agent spice-vdagent) ;;
    oracle)    pkgs=(virtualbox-guest-utils virtualbox-guest-x11) ;;
    microsoft) pkgs=(hyperv-daemons) ;;
  esac
  if (( ${#pkgs[@]} == 0 )); then
    info "Máquina $ETIQUETA_VIRT: no hay tools de invitado que instalar, fase omitida"
    return 0
  fi
  ejecutar "Instalando herramientas de invitado ($ETIQUETA_VIRT)" \
    apt-get install -y -qq --no-install-recommends "${pkgs[@]}"
}

fase_pentest() {
  titulo_fase "Fase 6/9 · Herramientas de reconocimiento (pipx + bbot)"
  if [[ $SIMULAR -eq 1 ]]; then
    paso_simulado "Instalando pipx (gestor de apps Python aisladas)"
    paso_simulado "Instalando bbot vía pipx para $USUARIO_REAL"
    paso_simulado "Instalando trivy (scanner de dependencias, lab SUPPLY-CHAIN) en /usr/local/bin + pre-carga de su DB de CVEs (~1.3GB)"
    paso_simulado "Instalando pip-audit (pipx, auditor de CVEs Python, lab SUPPLY-CHAIN)"
    paso_simulado "Verificando bbot (deps de sistema bajo demanda, con sudo del usuario)"
    paso_simulado "Creando ~/Herramientas y descargando eValidator.py, Cateyes.jpg, wayback_subdomains.sh, NmapDataExtractor.py, prueba.xml, clonando nmap-parse-output (ernw) e instalando greenbone.sh y labs.sh"
    paso_simulado "Deshabilitando servicios GVM por defecto (gvmd/ospd-openvas/gsad/notus-scanner) y bajándolos si están arriba"
    paso_simulado "Instalando dependencias Python de eValidator.py (requests)"
    paso_simulado "Creando enlace EXIF-READER en ~/Herramientas"
    paso_simulado "Creando enlaces RECON, OSINT y SCOPE en ~/Herramientas"
    paso_simulado "Instalando cupp (generador de diccionarios) en ~/Herramientas"
    paso_simulado "Instalando apache-scalp (Scalp!/Anathema) en ~/Herramientas + python3-regex + CLI scalp (pipx)"
    paso_simulado "Clonando ghauri (SQLi) + commix (OS Command Injection) + x8 (Hidden params) en ~/Herramientas"
    paso_simulado "Clonando git-dumper (dump de .git expuestos) en ~/Herramientas"
    paso_simulado "Instalando OWASP ZAP (zaproxy) desde apt"
    paso_simulado "Instalando gobuster (fuzzing dirs/DNS/vhosts) desde apt"
    paso_simulado "Instalando hashcat + wordlists (rockyou descomprimido) + dirb (common.txt de los laboratorios del manual)"
    paso_simulado "Instalando NetExec (nxc) para SMB/AD/RDP desde apt"
    paso_simulado "Instalando nuclei + actualizando plantillas"
    paso_simulado "Descargando gospider (spider rápido de URLs/archivos/JS)"
    paso_simulado "Compilando GoLinkFinder (0xsha)"
    paso_simulado "Descargando acccheck.py + badpdf.py + instalando impacket"
    paso_simulado "Instalando p0f y htop desde apt"
    paso_simulado "Instalando URLCrazy (typosquatting/homoglyphs) desde apt"
    paso_simulado "Instalando Burp Suite (proxy/scanner web) desde apt"
    paso_simulado "Descargando BurpIA.jar (extensión IA de Burp Suite)"
    paso_simulado "Instalando ISC DHCP client (isc-dhcp-client + ddns)"
    paso_simulado "Instalando Greenbone GVM/OpenVAS (metapaquete gvm + gvm-tools) desde apt"
    paso_simulado "Instalando enumerathor (apt deps + Go portable + findomain + OneForAll)"
    paso_simulado "Instalando Node.js (NodeSource) y chrome-devtools-mcp (npm global)"
    paso_simulado "Enlazando Chromium a /opt/google/chrome/chrome para el MCP"
    paso_simulado "Instalando @agent-sh/computer-use-linux (xdotool/wmctrl/at-spi2-core + doctor)"
    paso_simulado "Instalando opencode (CLI) para $USUARIO_REAL"
    paso_simulado "Instalando Bun + OCLoop (harness de bucles para opencode) en ~/Herramientas/ocloop"
    return 0
  fi
  instalar_herramientas
}

# Instala las herramientas de reconocimiento y el contenido de ~/Herramientas
# (pipx, bbot, eValidator.py, Cateyes.jpg y la dependencia requests).
# Todo se instala en el entorno del usuario ($USUARIO_REAL), nunca en root.
instalar_herramientas() {
  if command -v pipx >/dev/null 2>&1; then
    info "pipx ya está instalado ($(pipx --version))"
  elif (( EUID == 0 )); then
    ejecutar "Instalando pipx (apt)" apt-get install -y -qq --no-install-recommends pipx
  else
    # Sin root no se puede instalar pipx por apt; avisar y seguir con lo demás
    aviso "pipx no está instalado y requiere root: corré 'sudo $0 --herramientas' (o sudo $0) si lo necesitás."
  fi
  # Activar ~/.local/bin en el PATH del usuario real (idempotente: pipx
  # ensurepath solo escribe la línea si aún no está en ~/.bashrc / ~/.profile).
  # Hace que bbot y otras herramientas pipx sean invocables sin re-login.
  if command -v pipx >/dev/null 2>&1; then
    _como_usuario env PATH="$HOME_REAL/.local/bin:$PATH" pipx ensurepath >/dev/null 2>&1 || true
  fi
  # p0f: fingerprinting pasivo de tráfico de red · htop: monitor interactivo.
  # NetExec: ejecución/postexplotación AD/SMB/RDP/SSH/WinRM (Kali: binario nxc).
  # URLCrazy: variantes tipográficas de dominio (typosquatting/homoglyphs).
  local herramientas="$HOME_REAL/Herramientas"
  _asegurar_apt_pkg p0f
  _asegurar_apt_pkg htop
  # OWASP ZAP: proxy/scanner web open-source (Kali: zaproxy, binarios
  # zaproxy/owasp-zap en /usr/bin, java app en /usr/share/zaproxy).
  _asegurar_apt_pkg zaproxy zaproxy 'dpkg-query -W zaproxy 2>/dev/null'
  # ISC DHCP client: cliente DHCP y plugin de actualización DNS dinámica
  # (útil para renovación de leases y scripts de pentesting en red local).
  _asegurar_apt_pkg dhclient isc-dhcp-client 'dhclient --version 2>&1'
  _asegurar_apt_pkg dhclient isc-dhcp-client-ddns 'dhclient --version 2>&1'
  # Burp Suite (proxy/scanner web): GUI Java; --version no aplica (la valida
  # dpkg y el binario no la imprime sin launch completo).
  _asegurar_apt_pkg burpsuite burpsuite 'dpkg-query -W burpsuite 2>/dev/null'
  if command -v burpsuite >/dev/null 2>&1; then
    # Parchear UserConfig.json de Burp: apuntar al Chromium/Chrome resuelto
    # por _resolver_chromium_bin (DRY). Idempotente: si ya apunta al binario
    # correcto, no toca nada. Backup timestamp antes de escribir. Soporta los
    # dos schemas conocidos de Burp (2023.x = misc.embedded_browser, 2024+ =
    # browser.embedded_browser); si el schema cambia, deja el archivo intacto
    # y avisa en lugar de corromper la config del operador.
    local ucfg="$HOME_REAL/.BurpSuite/UserConfig.json"
    if [[ -f "$ucfg" ]]; then
      local chromium_bin
      chromium_bin="$(_resolver_chromium_bin)"
      if [[ -z "$chromium_bin" ]]; then
        aviso "Burp UserConfig: sin Chromium/Chrome en el sistema; no se parchea"
      else
        # Rutas por entorno (KDSIO_*), no por interpolación '$var' en el
        # código: un path con comilla simple rompería el python (y era
        # inyección si el home fuese hostil).
        ejecutar "Configurando Burp para usar $chromium_bin" \
          _como_usuario env HOME="$HOME_REAL" KDSIO_UCFG="$ucfg" \
            KDSIO_CHROMIUM="$chromium_bin" python3 -c "
import glob, json, os, shutil, sys
from datetime import datetime
p = os.environ['KDSIO_UCFG']
target = os.environ['KDSIO_CHROMIUM']
try:
    with open(p, encoding='utf-8') as f:
        d = json.load(f)
except (OSError, ValueError) as e:
    print(f'ERROR: UserConfig.json ilegible ({e}); no se modifica')
    sys.exit(1)
if not isinstance(d, dict):
    print('AVISO: UserConfig.json sin objeto raiz; no se modifica')
    sys.exit(0)
schemas = [
    ['user_options', 'misc',    'embedded_browser'],
    ['user_options', 'browser', 'embedded_browser'],
]
def _buscar(nodo, ruta):
    # Solo recorre dicts EXISTENTES: nunca fabrica {} huérfanos
    # desconectados de d (bug previo: node.get(k, {}) + dump(d) sin persistir
    # reportaba OK sin escribir nada).
    for k in ruta[:-1]:
        if not isinstance(nodo, dict):
            return None
        nxt = nodo.get(k)
        if not isinstance(nxt, dict):
            return None
        nodo = nxt
    if not isinstance(nodo, dict):
        return None
    return (nodo, nodo.get(ruta[-1]))
def _respaldar():
    # Backup SOLO al escribir (antes se creaba incluso en no-op) + rotación:
    # conserva los 3 más recientes, borra el resto.
    bkp = p + '.bak-' + datetime.now().strftime('%Y%m%d-%H%M%S')
    shutil.copy2(p, bkp)
    for viejo in sorted(glob.glob(p + '.bak-*'))[:-3]:
        try:
            os.remove(viejo)
        except OSError:
            pass
for ruta in schemas:
    hallado = _buscar(d, ruta)
    if hallado is None:
        continue
    nodo, hoja = hallado
    if isinstance(hoja, dict) and hoja.get('executable') == target:
        print(f'OK: ya apunta a {target}')
        sys.exit(0)
    _respaldar()
    nodo[ruta[-1]] = {'executable': target, 'enabled': True}
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    print('OK: schema=' + '.'.join(ruta) + ' -> ' + target)
    sys.exit(0)
# Ningún schema existe: crear el preferido con dicts ENLAZADOS a d.
nodo = d
for k in schemas[0][:-1]:
    nxt = nodo.get(k)
    if not isinstance(nxt, dict):
        nxt = {}
        nodo[k] = nxt
    nodo = nxt
_respaldar()
nodo[schemas[0][-1]] = {'executable': target, 'enabled': True}
with open(p, 'w', encoding='utf-8') as f:
    json.dump(d, f, indent=2, ensure_ascii=False)
print('OK: schema creado ' + '.'.join(schemas[0]) + ' -> ' + target)
sys.exit(0)
"
      fi
    else
      info "Burp aún no ha generado UserConfig.json (se parcheará al primer arranque)"
      aviso "Tras arrancar Burp por primera vez, corré de nuevo: sudo $0 --herramientas"
    fi
  fi

  # NetExec corre contra las librerías del apt (python3-sqlalchemy,
  # python3-impacket): cualquier copia pip --user las sombrea y lo rompe.
  _purgar_sombra_pip sqlalchemy
  _purgar_sombra_pip impacket
  _asegurar_apt_pkg urlcrazy
  # nuclei: escáner de vulnerabilidades. v3.11 no descarga templates con
  # -update-templates (sólo config); los templates viven en el repo público
  # projectdiscovery/nuclei-templates. Clonamos/actualizamos a ~/Herramientas/
  # nuclei-templates para que el operador los use con -t ~/Herramientas/nuclei-templates.
  _asegurar_apt_pkg nuclei nuclei 'nuclei -version 2>&1'
  # SecLists: wordlists de reconocimiento (params de x8, dir busting de ffuf, etc)
  _asegurar_apt_pkg seclists
  # Laboratorios del manual (PDFs servidos en /var/www/html/PDF):
  # - hashcat: CRYPTO-FAILURES crackea MD5 sin salt (hashcat -m 0 -a 0
  #   hash.txt rockyou.txt).
  # - wordlists: provee rockyou.txt.gz; Kali NO lo descomprime solo y el
  #   manual invoca rockyou.txt a secas → gunzip -k idempotente.
  # - dirb: SOLO por su wordlist /usr/share/wordlists/dirb/common.txt que
  #   gobuster consume con -w en el manual (el binario dirb no se usa en
  #   ningún PDF; verificado contra el texto de los 12 manuales).
  _asegurar_apt_pkg hashcat hashcat 'hashcat --version 2>&1'
  _asegurar_apt_pkg wordlists wordlists 'dpkg-query -W wordlists 2>/dev/null'
  _asegurar_apt_pkg dirb dirb 'dpkg-query -W dirb 2>/dev/null'
  local rk_txt=/usr/share/wordlists/rockyou.txt
  if [[ ! -s "$rk_txt" && -s "$rk_txt.gz" ]]; then
    ejecutar "Descomprimiendo rockyou.txt (el manual lo usa sin extension)" gunzip -k "$rk_txt.gz"
  fi
  # gobuster: fuzzing de dirs/DNS/vhosts/S3. Paquete mantenido en Kali
  # (binario nativo por arch): apt-first, sin binarios externos ni Go portable.
  _asegurar_apt_pkg gobuster gobuster 'gobuster version 2>&1'
  if command -v nuclei >/dev/null 2>&1; then
    local nuc_tpl="$herramientas/nuclei-templates"
    # kind=feed: fetch+reset --hard contra origin/HEAD. Con pull --ff-only
    # fallaba en silencio cuando el upstream diverge (force-push/merge), y el
    # operador acababa con templates obsoletos creyendo que estaban al día.
    _git_clonar "$nuc_tpl" \
      "https://github.com/projectdiscovery/nuclei-templates.git" \
      "nuclei-templates" feed
    # --- Fuente única de verdad para nuclei ---
    # nuclei mantiene SU store en ~/.local/nuclei-templates vía
    # ~/.config/nuclei/.templates-config.json (clave nuclei-templates-directory,
    # schema verificado con nuclei 3.x). Dos stores = deriva garantizada: el
    # operador actualiza uno y escanea con el otro. Apuntamos el store de
    # nuclei al clon git (backup previo, coherente con la política del script).
    # Si `nuclei -update-templates` reescribe el json, el próximo pase lo
    # re-parchea (idempotente, self-healing).
    local nuc_tcfg="$HOME_REAL/.config/nuclei/.templates-config.json"
    if [[ -s "$nuc_tcfg" ]]; then
      if grep -q "\"nuclei-templates-directory\"[[:space:]]*:[[:space:]]*\"$nuc_tpl\"" "$nuc_tcfg" 2>/dev/null; then
        info "nuclei store ya apunta a ~/Herramientas/nuclei-templates"
      else
        ejecutar "Apuntando nuclei store al clon canónico (fuente única)" \
          _como_usuario env HOME="$HOME_REAL" KDSIO_TPL="$nuc_tpl" KDSIO_TCFG="$nuc_tcfg" \
          python3 -c '
import json, os, shutil, sys
p = os.environ["KDSIO_TCFG"]; tpl = os.environ["KDSIO_TPL"]
with open(p, encoding="utf-8") as f:
    d = json.load(f)
cur = d.get("nuclei-templates-directory", "")
if cur == tpl:
    print("OK: ya apunta a " + tpl); sys.exit(0)
shutil.copy2(p, p + ".bak-kdsio")
# Rebase del store principal Y los sub-stores (s3/github/gitlab/azure cuelgan
# del mismo directorio en el schema de nuclei).
old = cur.rstrip("/") if cur else None
for k, v in list(d.items()):
    if isinstance(v, str) and old and v.startswith(old + "/"):
        d[k] = tpl + v[len(old):]
d["nuclei-templates-directory"] = tpl
with open(p, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=2)
print("OK: " + (cur or "<sin-valor>") + " -> " + tpl)
'
      fi
    else
      info "nuclei aún no generó .templates-config.json (se parchea al primer arranque de nuclei)"
    fi
  fi
      # Nessus (Tenable): escáner de vulnerabilidades comercial con feed propio.
  # Descarga directa desde la API de Tenable detectando arquitectura/versión;
  # el .deb oficial instala /opt/nessus + nessusd.service + nessuscli.
  # Instalador externo (heredoc con comillas simples) para evitar triple-comillas
  # en bash -c. nessus.sh se embebe igual que greenbone.sh.
  if [[ -x /opt/nessus/sbin/nessuscli ]]; then
    info "Nessus ya está instalado ($(/opt/nessus/sbin/nessuscli --version 2>/dev/null | head -1))"
  elif (( EUID == 0 )); then
    # Instalador en mktemp (antes /tmp fijo predecible) con limpieza en ambas
    # ramas; el heredoc interno lleva pipefail para no enmascarar dpkg -i.
    # La arch canónica viaja por entorno KDSIO_ARCH (un valor, sin aliases).
    local nessus_inst
    nessus_inst=$(mktemp /tmp/kdsio-install-nessus.XXXXXX)
    cat > "$nessus_inst" <<'NESSUS_INSTALL_EOF'
#!/usr/bin/env bash
set -e -o pipefail
# arch canónica desde KDSIO_ARCH (amd64|arm64|armhf|i386|unknown). Si no
# llega, fallback a uname -m mapeado al esquema Debian (mismo que el padre).
_arch="${KDSIO_ARCH:-}"
if [[ -z "$_arch" ]]; then
  case "$(uname -m)" in
    x86_64)        _arch=amd64 ;;
    aarch64)       _arch=arm64 ;;
    armv7l|armv6l) _arch=armhf ;;
    i386|i686)     _arch=i386 ;;
    *)             _arch=unknown ;;
  esac
fi
# Mapa de arquitectura CPU → variantes oficiales de paquete Tenable.
# El orden importa: probamos la preferida y hacemos fallback si falla.
declare -a casos
case "$_arch" in
  amd64)
    casos=(debian10_amd64 ubuntu1604_amd64)
    ;;
  arm64)
    casos=(ubuntu1804_aarch64)
    ;;
  armhf)
    casos=(raspberrypios_armhf)
    ;;
  i386)
    casos=(ubuntu1604_i386)
    ;;
  *)
    echo "[!] Arquitectura $_arch sin paquete Nessus oficial"; exit 0 ;;
esac
# Descargar la API una vez y elegir la primera variante disponible.
api_json=$(curl -fsSL --retry 3 --max-time 60 'https://www.tenable.com/downloads/api/v2/pages/nessus')
pkg_url=$(echo "$api_json" | python3 -c "
import sys, json
casos = sys.argv[1:]
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
def walk(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for it in obj:
            if isinstance(it, dict): yield from walk(it)
    elif isinstance(obj, str):
        yield obj
files = list(walk(d))
for caso in casos:
    matches = [f for f in files if f.endswith(caso + '.deb') and f.startswith('Nessus-')]
    if matches:
        print(matches[-1])
        break
else:
    # Fallback genérico por arquitectura (los tags de distro de Tenable
    # envejecen: debian10/ubuntu1604 → cualquier Nessus-*-<arch>.deb).
    import platform
    debarch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'armv7l': 'armhf',
               'armhf': 'armhf', 'i386': 'i386', 'i686': 'i386'}.get(platform.machine(), '')
    if debarch:
        gen = sorted(f for f in files
                     if f.startswith('Nessus-') and f.endswith('_' + debarch + '.deb'))
        if gen:
            print(gen[-1])
" "${casos[@]}")
if [[ -z "$pkg_url" ]]; then
  echo "[!] No encontré paquete Nessus para $_arch (probados: ${casos[*]})"
  exit 0
fi
# Resolver URL absoluta vs relativa (la API devuelve ambas formas).
if [[ "$pkg_url" == http* ]]; then
  url="$pkg_url"
else
  url="https://www.tenable.com/downloads/api/v2/pages/nessus/files/${pkg_url#/?files/}"
fi
pkg=$(basename "$url")
echo "[i] Descargando $pkg (~70MB) ..."
tmp=$(mktemp -d); cd "$tmp"
curl -fsSL --retry 3 --max-time 600 -o "$pkg" "$url" || { echo "[!] Descarga falló"; exit 1; }
echo "[i] Instalando $pkg ..."
dpkg -i "$pkg" 2>&1 | tail -3 || { echo "[!] dpkg -i falló"; exit 1; }
# Post-install: Nessus consume RAM/CPU: deshabilitar auto-arranque.
if [[ -x /bin/systemctl ]]; then
  systemctl disable nessusd 2>/dev/null || true
fi
cd /; rm -rf "$tmp"
# Verificación final
if [[ -x /opt/nessus/sbin/nessuscli ]]; then
  echo "[+] Nessus instalado correctamente: $(/opt/nessus/sbin/nessuscli --version 2>&1 | head -1)"
else
  echo "[!] Instalación completada pero nessuscli no encontrado en /opt/nessus/sbin"
  exit 1
fi
NESSUS_INSTALL_EOF
    # Gate antes de descargar ~70MB+ (Nessus instala /opt/nessus ≈ 600MB).
    if ! _gate_disco 1024 "instalar Nessus" || ! _gate_red "instalar Nessus"; then
      rm -f "$nessus_inst"
    else
      ejecutar "Instalando Nessus (Tenable)" env KDSIO_ARCH="$KDSIO_ARCH" bash "$nessus_inst"
    fi
    rm -f "$nessus_inst" 2>/dev/null || true
    # Verificación post-instalación: confirmar que nessuscli existe y responde.
    # El pipe VA DENTRO del bash -c: antes aplicaba a `ejecutar` y su rc se
    # perdía (además de imprimir fuera del formato de pasos).
    if [[ -x /opt/nessus/sbin/nessuscli ]]; then
      ejecutar "Verificando Nessus instalado" bash -c '/opt/nessus/sbin/nessuscli --version 2>&1 | head -1'
    fi
  else
    aviso "Nessus no está instalado y requiere root: corré 'sudo $0 --herramientas' (o sudo $0) si lo necesitás."
  fi
  # nessus.sh: gestor start/stop/restart/status/setup/plugin-update embebido (sin red).
  # Importante: nessus_sh se declara aquí aunque su uso dependa de la existencia
  # de Nessus en el sistema; nessus.sh funciona perfectamente para reportar
  # "no instalado" sin requerir dpkg.
  local nessus_sh="$herramientas/nessus.sh"
  if [[ -x "$nessus_sh" ]] && grep -q "nessus.sh · Gestión" "$nessus_sh"; then
    info "nessus.sh ya está en $nessus_sh"
  else
    ejecutar "Instalando nessus.sh (start|stop|status|setup|plugin-update) en ~/Herramientas" \
      _como_usuario bash -c "mkdir -p '$herramientas' && cat > '$nessus_sh.tmp' && chmod +x '$nessus_sh.tmp' && mv '$nessus_sh.tmp' '$nessus_sh'" <<'NESSUS_EOF'
#!/usr/bin/env bash
# ============================================================
#  nessus.sh · Gestión del servicio Nessus (Tenable)
#  KALI-DSIO · DragonJAR.org
#
#  Uso:      sudo ./nessus.sh start
#            sudo ./nessus.sh stop
#            sudo ./nessus.sh restart
#            ./nessus.sh status
#            sudo ./nessus.sh setup         (1ª vez: inicializa Nessus + plugins)
#            sudo ./nessus.sh update        (nessuscli update --all: plugins + software)
#            sudo ./nessus.sh plugin-update (solo plugins)
#            sudo ./nessus.sh password <usuario> <nueva>
#            ./nessus.sh logs               (tail -f del log)
#
#  Web UI:   https://127.0.0.1:8834/
#
#  NOTAS:
#  · Nessus queda DESHABILITADO en el arranque del sistema por diseño: solo
#    se levanta de forma explícita con este script (consume RAM/CPU).
#  · 'setup' descarga +500MB de plugins la primera vez (varios minutos).
#  · Nessus Essentials requiere registrarte en tenable.com para obtener una
#    Activation Code gratuita; se necesita cuando el wizard web te la pida.
# ============================================================
set -u -o pipefail

SERVICIO="nessusd"
PORT="8834"
URL="https://127.0.0.1:${PORT}"
NESSUSCLI=/opt/nessus/sbin/nessuscli
NESSUS_OPT="/opt/nessus"
LOG="/opt/nessus/var/nessus/logs/nessusd.log"
NESSUS_USER="${NESSUS_USER:-nessusd}"
NESSUS_GROUP="${NESSUS_GROUP:-nessusd}"

ROJO=$'\033[01;31m'; VERDE=$'\033[01;32m'; AMAR=$'\033[01;33m'; CIAN=$'\033[01;36m'; RESET=$'\033[00m'

ok()   { printf '%s[+]%s %s\n' "$VERDE" "$RESET" "$1"; }
err()  { printf '%s[-]%s %s\n' "$ROJO" "$RESET" "$1" >&2; }
info() { printf '%s[i]%s %s\n' "$CIAN" "$RESET" "$1"; }
warn() { printf '%s[!]%s %s\n' "$AMAR" "$RESET" "$1"; }

requiere_root() {
  if (( EUID != 0 )); then err "Esta acción requiere root: sudo $0 $1"; exit 1; fi
}
nessus_instalado() { [[ -x "$NESSUSCLI" ]]; }
servicio_activo() { systemctl is-active --quiet "$1" 2>/dev/null; }

plugin_update_en_curso() {
  pgrep -f "nessuscli.*plugin-update\|nessusd.*update" >/dev/null 2>&1 \
    || pgrep -f "nessusd: Plugin" >/dev/null 2>&1
}

esperar_puerto() {
  local limite="${1:-60}" i
  info "Esperando Nessus en ${PORT}/tcp (máx ${limite}s) ..."
  for ((i = 0; i < limite; i++)); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 1
  done; return 1
}

levantar() {
  requiere_root start
  if ! nessus_instalado; then err "Nessus no está instalado: sudo apt-get install -y ./Nessus*.deb"; exit 1; fi
  if servicio_activo "$SERVICIO"; then info "Nessus ya está corriendo (${URL})"; return 0; fi
  if command -v lsof >/dev/null 2>&1 && lsof -Pi ":${PORT}" -sTCP:LISTEN -t >/dev/null 2>&1; then
    err "El puerto ${PORT}/tcp ya está ocupado:"; lsof -Pi ":${PORT}" -sTCP:LISTEN; exit 1
  fi
  info "Levantando $SERVICIO ..."
  systemctl start "$SERVICIO" 2>/dev/null
  if esperar_puerto 90; then
    ok "Nessus disponible en ${URL}"
    ok "Si es la primera vez, completá el wizard web y pegá tu Activation Code"
  else
    warn "Nessus sigue arrancando (primera vez compila plugins, puede tardar minutos)"
    warn "  Reintentá: $0 status"
  fi
}

detener() {
  requiere_root stop
  if ! nessus_instalado; then err "Nessus no está instalado"; exit 1; fi
  if plugin_update_en_curso; then
    err "Hay una actualización de plugins en curso."
    err "Detener Nessus ahora puede CORROMPER la base de plugins."
    err "Esperá a que termine (controlalo con 'nessus.sh status')."
    exit 1
  fi
  info "Deteniendo $SERVICIO ..."
  systemctl stop "$SERVICIO" 2>/dev/null
  ok "Nessus detenido (sigue deshabilitado en el arranque del sistema)"
}

estado() {
  printf '%s=== ESTADO DE NESSUS ===%s\n' "$CIAN" "$RESET"
  if nessus_instalado; then
    local ver
    ver=$("$NESSUSCLI" --version 2>/dev/null | head -1 || echo "n/a")
    printf '  Binario          : %s (%s)\n' "${VERDE}instalado${RESET}" "$ver"
  else
    printf '  Binario          : %s\n' "${ROJO}no instalado${RESET}"
  fi
  if servicio_activo "$SERVICIO"; then
    printf '  Servicio         : %s\n' "${VERDE}activo${RESET}"
  elif systemctl is-enabled --quiet "$SERVICIO" 2>/dev/null; then
    printf '  Servicio         : %s\n' "${AMAR}parado pero HABILITADO en boot${RESET}"
  else
    printf '  Servicio         : %s\n' "${ROJO}parado (disabled)${RESET}"
  fi
  printf '\n'
  if servicio_activo "$SERVICIO"; then
    ok "Web UI disponible en ${URL}"
  else
    info "Web UI apagada: sudo $0 start"
  fi
  printf '\n'
  if plugin_update_en_curso; then
    warn "ACTUALIZACIÓN DE PLUGINS EN CURSO: NO detengas Nessus hasta que termine"
    warn "(descarga ~500MB + compilación, varios minutos la primera vez)"
    printf '\n'
  fi
  systemctl --no-pager -l status "$SERVICIO" 2>/dev/null | grep -E "●|Active:" | sed 's/^ */  /'
}

reiniciar() {
  requiere_root restart
  if plugin_update_en_curso; then
    err "Hay una actualización de plugins en curso: no se puede reiniciar."
    err "Esperá a que termine (controlalo con 'nessus.sh status')."
    exit 1
  fi
  systemctl stop "$SERVICIO" 2>/dev/null; sleep 2; levantar
}

setup() {
  requiere_root setup
  if ! nessus_instalado; then err "Nessus no está instalado"; exit 1; fi
  info "Inicializando Nessus (descarga +500MB de plugins, varios minutos)..."
  "$NESSUSCLI" managed --disable 2>/dev/null || true
  "$NESSUSCLI" install --quiet 2>/dev/null || true
  ok "Nessus inicializado. Activá con tu Activation Code desde ${URL}"
  info "Si Nessus no está corriendo: sudo $0 start"
}

plugin_update() {
  requiere_root plugin-update
  if plugin_update_en_curso; then
    err "Ya hay una actualización de plugins en curso: no lanzo otra en paralelo."
    exit 1
  fi
  if ! nessus_instalado; then err "Nessus no está instalado"; exit 1; fi
  info "Actualizando plugins (descarga +500MB y compilación)..."
  "$NESSUSCLI" update --plugins-only
  ok "Plugins actualizados. Monitoreá con 'nessus.sh status'"
}

update_all() {
  requiere_root update
  if plugin_update_en_curso; then
    err "Ya hay una actualización en curso: no lanzo otra en paralelo."
    exit 1
  fi
  if ! nessus_instalado; then err "Nessus no está instalado"; exit 1; fi
  warn "update --all: actualiza plugins Y el software Nessus (pide reinicio del servicio al final)."
  "$NESSUSCLI" update --all
  ok "Actualización completa finalizada"
  info "Recomendado: sudo $0 restart  (para que nessusd cargue la nueva versión)"
}

cambiar_password() {
  local req_user="${1:-}" nueva="${2:-}"
  if [[ -z "$req_user" || -z "$nueva" ]]; then err "Uso: sudo $0 password <usuario> <nueva>"; exit 1; fi
  requiere_root password
  "$NESSUSCLI" chpasswd "$req_user"
  ok "Contraseña de '$req_user' actualizada"
}

desinstalar() {
  requiere_root uninstall
  warn "Esto detiene Nessus, lo desinstala y BORRA /opt/nessus"
  warn "Tus escaneos y configuraciones se perderán."
  read -r -p "¿Confirmás? (sí/no): " ans
  [[ "$ans" == "sí" || "$ans" == "si" || "$ans" == "s" || "$ans" == "yes" ]] || { info "Cancelado"; exit 0; }
  systemctl disable --now "$SERVICIO" 2>/dev/null || true
  if dpkg -l nessus >/dev/null 2>&1; then
    apt-get -y remove nessus
  fi
  rm -rf /opt/nessus
  ok "Nessus desinstalado"
}

ver_logs() {
  warn "Mostrando logs en vivo (Ctrl+C para salir)"
  [[ -r "$LOG" ]] || { err "No puedo leer $LOG (usá sudo)"; exit 1; }
  tail -f "$LOG"
}

case "${1:-}" in
  start)             levantar ;;
  stop)              detener ;;
  restart)           reiniciar ;;
  status)            estado ;;
  setup)             setup ;;
  plugin-update)     plugin_update ;;
  update)            update_all ;;
  password)          shift; cambiar_password "$@" ;;
  uninstall)         desinstalar ;;
  logs)              ver_logs ;;
  -h|--help|"")      sed -n '2,26p' "$0" ;;
  *) err "Acción desconocida: '$1' (usa start|stop|restart|status|setup|plugin-update|password|logs|uninstall)"; exit 1 ;;
esac
NESSUS_EOF
  fi
  # Política por defecto: nessusd queda DESHABILITADO en el arranque del sistema
  # (consume RAM/CPU + bloquea puerto 8834). El operador lo levanta con nessus.sh start.
  if [[ -x /opt/nessus/sbin/nessuscli ]]; then
    if systemctl is-enabled --quiet nessusd 2>/dev/null; then
      systemctl disable nessusd >/dev/null 2>&1 || true
      info "Servicio 'nessusd' deshabilitado en el arranque (se levanta solo con nessus.sh start)"
    fi
    systemctl stop nessusd >/dev/null 2>&1 || true
  fi
  # Greenbone (GVM/OpenVAS): escáner de vulnerabilidades completo. El metapaquete
  # 'gvm' trae gvmd (manager), openvas-scanner, ospd-openvas, gsad (web UI), y los
  # scripts gvm-setup/gvm-start/gvm-stop/gvm-check-setup; gvm-tools añade clientes
  # GMP por consola. Los servicios quedan deshabilitados: se gestionan con gvm-start.
  # La primera sincronización de NVT (gvm-feed-update) descarga gigas y tarda horas:
  # no se lanza aquí, se deja para el primer arranque manual del operador.
  local gvm_ok=0
  if command -v gvm-check-setup >/dev/null 2>&1 && [[ -x /usr/sbin/gsad ]]; then
    gvm_ok=1
    info "Greenbone GVM ya está instalado ($(gvmd --version 2>/dev/null | head -1))"
    if [[ -d /var/lib/openvas/plugins ]] && [[ -n "$(ls -A /var/lib/openvas/plugins 2>/dev/null)" ]]; then
      local nvt_count
      nvt_count=$(find /var/lib/openvas/plugins/ -maxdepth 1 -name '*.nasl' 2>/dev/null | wc -l)
      info "Feed OpenVAS sincronizado previamente (~$nvt_count NVT .nasl)"
    else
      aviso "Feed OpenVAS sin sincronizar: ejecutá 'gvm-feed-update' antes del primer escaneo (descarga pesada, tarda horas)."
    fi
  elif (( EUID == 0 )); then
    # GVM no descarga nada durante apt install (los feeds se sincronizan
    # después con gvm-feed-update); pero la instalación de paquetes ocupa
    # ~400MB y los servicios consumen RAM. Gate suave de RAM: omitir si < 2GB.
    if _gate_ram 2048 "instalar Greenbone GVM"; then
      # ejecutar() propaga rc real (return $rc). gvm_ok se setea en base al
      # resultado; antes `gvm_ok=0; (( $? == 0 )) && gvm_ok=1` era siempre
      # verdadero (asignación reseteaba $? antes de la comparación).
      if ejecutar "Instalando Greenbone GVM/OpenVAS (metapaquete gvm + gvm-tools, apt)" \
          apt-get install -y -qq gvm gvm-tools; then
        gvm_ok=1
      else
        gvm_ok=0
        aviso "GVM no se pudo instalar (rc != 0): greenbone.sh se omite"
      fi
    fi
  else
    aviso "Greenbone GVM no está instalado y requiere root: corré 'sudo $0 --herramientas' (o sudo $0) si lo necesitás."
  fi
  if (( gvm_ok == 1 )) && ! systemctl is-enabled gvmd.service >/dev/null 2>&1; then
    info "Servicios GVM (gvmd/ospd-openvas) deshabilitados por defecto: arranquelos con 'gvm-start'"
  fi
  # labs.sh: gestor de Apache + labs del curso. Se embebe en heredoc (mismo
  # patrón que greenbone.sh). Requiere apache2 (se instala si falta y hay
  # root+red). Los labs en sí se copian a mano en /var/www/html.
  if command -v apache2 >/dev/null 2>&1; then
    info "apache2 ya está instalado ($(apache2 -v 2>/dev/null | head -1 | awk '{print $3}'))"
  elif (( EUID == 0 )) && [[ "$KDSIO_RED" == "ok" ]]; then
    ejecutar "Instalando apache2 (servidor de los laboratorios)" \
      apt-get install -y -qq --no-install-recommends apache2
  else
    aviso "apache2 no está instalado: labs.sh se instala igual, pero 'labs.sh start' lo exigirá"
  fi
  local labs_sh="$herramientas/labs.sh"
  if [[ -x "$labs_sh" ]] && grep -q "labs.sh · Levanta Apache" "$labs_sh"; then
    info "labs.sh ya está en $labs_sh"
  else
    ejecutar "Instalando labs.sh (start|stop|status|open|urls) en ~/Herramientas" \
      _como_usuario bash -c "mkdir -p '$herramientas' && cat > '$labs_sh.tmp' && chmod +x '$labs_sh.tmp' && mv '$labs_sh.tmp' '$labs_sh'" <<'LABS_EOF'
#!/usr/bin/env bash
# ============================================================
#  labs.sh · Levanta Apache y abre los laboratorios DSIO en el navegador
#  KALI-DSIO · DragonJAR.org
#
#  Uso:      sudo ./labs.sh start     (levanta apache2 + abre labs)
#            sudo ./labs.sh stop      (detiene apache2)
#            ./labs.sh status         (estado de apache2 + puerto 80)
#            ./labs.sh open           (abre las pestañas, sin tocar apache)
#            ./labs.sh urls           (imprime las URLs de los labs)
#
#  Base:     http://127.0.0.1/
#  Labs:     /var/www/html/<LAB>/   (AUTH-FAILURES, XSS, XXE, ...)
#
#  NOTAS:
#  · start requiere root para systemctl (apache2); el navegador se abre
#    como el USUARIO real ($SUDO_USER), nunca como root.
#  · Cada lab detecta su página de entrada (login.php > inicio.php >
#    index.php > index.html) escaneando /var/www/html en tiempo real:
#    los labs nuevos del curso aparecen solos.
#  · En navegadores Gecko el multi-tab usa firefox --new-tab (una sola
#    ventana); en Chromium usa chromium --new-tab; fallback: xdg-open
#    por URL (puede abrir varias ventanas).
# ============================================================
set -u -o pipefail

WEBROOT="/var/www/html"
PUERTO="80"
BASE="http://127.0.0.1"
ENTRADAS_PREFERIDAS=(login.php inicio.php index.php index.html)

ROJO=$'\033[01;31m'; VERDE=$'\033[01;32m'; AMAR=$'\033[01;33m'; CIAN=$'\033[01;36m'; RESET=$'\033[00m'

ok()   { printf '%s[+]%s %s\n' "$VERDE" "$RESET" "$1"; }
err()  { printf '%s[-]%s %s\n' "$ROJO" "$RESET" "$1" >&2; }
info() { printf '%s[i]%s %s\n' "$CIAN" "$RESET" "$1"; }
warn() { printf '%s[!]%s %s\n' "$AMAR" "$RESET" "$1"; }

requiere_root() {
  if (( EUID != 0 )); then err "Esta acción requiere root: sudo $0 $1"; exit 1; fi
}

# Detecta el archivo de entrada de un lab: $1 = ruta al directorio
entrada_lab() {
  local d="$1" cand
  for cand in "${ENTRADAS_PREFERIDAS[@]}"; do
    [[ -f "$d/$cand" ]] && { echo "$cand"; return 0; }
  done
  return 1
}

# Descubre labs: directorios del webroot que tengan página de entrada.
# Siempre incluye el índice general ($WEBROOT/index.html) como primera URL.
descubrir_labs() {
  local d base entrada
  [[ -f "$WEBROOT/index.html" ]] && echo "$BASE/"
  for d in "$WEBROOT"/*/; do
    [[ -d "$d" ]] || continue
    base=$(basename "$d")
    entrada=$(entrada_lab "$d") || continue
    echo "$BASE/$base/$entrada"
  done
}

# Usuario gráfico real: si corre con sudo, abre el navegador con el usuario
# original (DISPLAY/XAUTHORITY de la sesión gráfica), nunca como root.
usuario_grafico() { echo "${SUDO_USER:-$USER}"; }

# Abre URLs como usuario gráfico; $@ = lista de URLs
abrir_en_navegador() {
  local uReal DISPLAY_X XAUTH_X navegador
  uReal=$(usuario_grafico)
  DISPLAY_X="${DISPLAY:-:0}"
  XAUTH_X=""
  [[ -n "${XAUTHORITY:-}" ]] && XAUTH_X="$XAUTHORITY"

  navegador="$(sudo -u "$uReal" env DISPLAY="$DISPLAY_X" xdg-settings get default-web-browser 2>/dev/null || true)"

  # URLs de Gecko en una sola invocación (una ventana con N pestañas)
  if [[ "$navegador" == *firefox* ]]; then
    sudo -u "$uReal" env DISPLAY="$DISPLAY_X" ${XAUTH_X:+XAUTHORITY="$XAUTH_X"} \
      firefox --new-tab "$@" >/dev/null 2>&1 && return 0
  elif [[ "$navegador" == *chrom* ]]; then
    local u
    for u in "$@"; do
      sudo -u "$uReal" env DISPLAY="$DISPLAY_X" ${XAUTH_X:+XAUTHORITY="$XAUTH_X"} \
        chromium --new-tab "$u" >/dev/null 2>&1
    done
    return 0
  fi

  # Fallback: xdg-open URL por URL
  local u
  for u in "$@"; do
    sudo -u "$uReal" env DISPLAY="$DISPLAY_X" ${XAUTH_X:+XAUTHORITY="$XAUTH_X"} \
      xdg-open "$u" >/dev/null 2>&1
  done
}

apache_activo() { systemctl is-active --quiet apache2 2>/dev/null; }

puerto_80_arriba() { (exec 3<>"/dev/tcp/127.0.0.1/$PUERTO") 2>/dev/null; }

esperar_http() {
  local limite="${1:-15}" i
  info "Esperando Apache en $PUERTO/tcp (máx ${limite}s) ..."
  for ((i = 0; i < limite; i++)); do
    puerto_80_arriba && return 0
    sleep 1
  done
  return 1
}

levanta_apache() {
  if ! command -v apache2 >/dev/null 2>&1; then
    err "apache2 no está instalado: sudo apt-get install -y apache2"
    exit 1
  fi
  if apache_activo; then
    ok "apache2 ya está activo"
  else
    info "Iniciando apache2 ..."
    systemctl start apache2
    if ! esperar_http 15; then
      err "apache2 no levantó el puerto $PUERTO. Revisá: systemctl status apache2"
      exit 1
    fi
    ok "Apache sirviendo en $BASE"
  fi
}

levantar() {
  requiere_root start
  levanta_apache
  info "Abriendo el índice de laboratorios en el navegador ..."
  abrir_en_navegador "$BASE/"
  ok "Laboratorios disponibles: $BASE"
}

detener() {
  requiere_root stop
  if apache_activo; then
    systemctl stop apache2
    ok "apache2 detenido"
  else
    info "apache2 ya está inactivo"
  fi
}

estado() {
  if apache_activo; then
    ok "apache2: activo"
  else
    warn "apache2: inactivo"
  fi
  if puerto_80_arriba; then
    ok "Puerto $PUERTO/tcp: escuchando ($BASE)"
  else
    warn "Puerto $PUERTO/tcp: cerrado"
  fi
  info "Labs disponibles en $WEBROOT:"
  descubrir_labs | sed 's/^/    /'
}

# open [LAB|--labs]: por defecto abre solo el índice; con un nombre de lab
# (XSS, SSRF, ...) abre ese lab; con --labs abre índice + una pestaña por lab.
solo_abrir() {
  if ! puerto_80_arriba; then
    err "Apache no está sirviendo en $PUERTO/tcp: corré 'sudo $0 start' primero"
    exit 1
  fi
  local dest="${1:-}"
  if [[ -z "$dest" ]]; then
    info "Abriendo el índice de laboratorios en el navegador ..."
    abrir_en_navegador "$BASE/"
    ok "Laboratorios disponibles: $BASE"
    return 0
  fi
  if [[ "$dest" == "--labs" || "$dest" == "-t" ]]; then
    local urls
    urls=$(descubrir_labs)
    if [[ -z "$urls" ]]; then
      warn "No se encontraron labs en $WEBROOT"
      exit 1
    fi
    info "Abriendo $(wc -l <<<"$urls") pestañas en el navegador ..."
    abrir_en_navegador $urls
    ok "Laboratorios abiertos: $BASE"
    return 0
  fi
  local entrada
  if ! entrada="$(entrada_lab "$WEBROOT/$dest")"; then
    err "Lab desconocido: $dest (mirá ./labs.sh status para el listado)"
    exit 1
  fi
  info "Abriendo lab $dest ..."
  abrir_en_navegador "$BASE/$dest/$entrada"
  ok "Lab abierto: $BASE/$dest/$entrada"
}

mostrar_urls() {
  descubrir_labs
}

case "${1:-start}" in
  start)  levantar ;;
  stop)   detener ;;
  status) estado ;;
  open)   shift; solo_abrir "${1:-}" ;;
  urls)   mostrar_urls ;;
  -h|--help|ayuda)
    sed -n '2,16p' "$0" | sed 's/^# \{0,2\}//'
    ;;
  *) err "Acción desconocida: $1 (ayuda: $0 --help)"; exit 2 ;;
esac
LABS_EOF
  fi
  if (( gvm_ok == 1 )); then
    local gb_sh="$herramientas/greenbone.sh"
    if [[ -x "$gb_sh" ]] && grep -q "greenbone.sh · Gestión" "$gb_sh"; then
      info "greenbone.sh ya está en $gb_sh"
    else
      # Se embebe el script en heredoc (sin descarga de red) porque el repo
      # DragonJAR/Scripts solo aloja el script principal; el gestor de servicios
      # viaja dentro del propio KALI-DSIO.sh.
      ejecutar "Instalando greenbone.sh (start|stop|restart|status|feed-update|password) en ~/Herramientas" \
        _como_usuario bash -c "mkdir -p '$herramientas' && cat > '$gb_sh.tmp' && chmod +x '$gb_sh.tmp' && mv '$gb_sh.tmp' '$gb_sh'" <<'GREENBONE_EOF'
#!/usr/bin/env bash
# ============================================================
#  greenbone.sh · Gestión de servicios GVM/OpenVAS (Greenbone)
#  KALI-DSIO · DragonJAR.org
#
#  Uso:      sudo ./greenbone.sh start
#            sudo ./greenbone.sh stop
#            sudo ./greenbone.sh restart
#            ./greenbone.sh status
#            sudo ./greenbone.sh setup          (primera vez: BD + admin + feeds)
#            sudo ./greenbone.sh wait-ready     (espera import de configs en gvmd)
#            sudo ./greenbone.sh feed-update
#            sudo ./greenbone.sh password <usuario> <nueva>
#            ./greenbone.sh logs                (tail -f gvmd + ospd)
#
#  Web UI:   https://127.0.0.1:9392
#
#  NOTAS:
#  · Los servicios GVM (gvmd, ospd-openvas, gsad, notus-scanner) quedan
#    DESHABILITADOS en el arranque del sistema por diseño: solo se levantan
#    de forma explícita con este script.
#  · Tras 'setup' el wizard web "Quick first scan" falla con
#    "default Scan Config is not available" HASTA que gvmd importe los
#    configs a su BD (puede tardar 10-30 min: SCAP/CPEs son pesados).
#    Monitoreá con: ./greenbone.sh status  o  ./greenbone.sh wait-ready
# ============================================================
set -u -o pipefail

SERVICIOS=(gvmd ospd-openvas gsad notus-scanner)
PORT="9392"
URL="https://127.0.0.1:${PORT}"
FEED_LOG="/var/log/gvm/gvmd.log"
OSPD_LOG="/var/log/gvm/ospd-openvas.log"
PLUGINS_DIR="/var/lib/openvas/plugins"

ROJO=$'\033[01;31m'; VERDE=$'\033[01;32m'; AMAR=$'\033[01;33m'; CIAN=$'\033[01;36m'; RESET=$'\033[00m'

ok()   { printf '%s[+]%s %s\n' "$VERDE" "$RESET" "$1"; }
err()  { printf '%s[-]%s %s\n' "$ROJO" "$RESET" "$1" >&2; }
info() { printf '%s[i]%s %s\n' "$CIAN" "$RESET" "$1"; }
warn() { printf '%s[!]%s %s\n' "$AMAR" "$RESET" "$1"; }

requiere_root() {
  if (( EUID != 0 )); then err "Esta acción requiere root: sudo $0 $1"; exit 1; fi
}
gvm_instalado() { command -v gvmd >/dev/null 2>&1; }
servicio_activo() { systemctl is-active --quiet "$1" 2>/dev/null; }

sync_en_curso() {
  pgrep -f "greenbone-feed-sync" >/dev/null 2>&1 \
    || pgrep -f "gvmd --(re)?build" >/dev/null 2>&1 \
    || pgrep -f "rsync.*feed\.community\.greenbone" >/dev/null 2>&1
}

nvts_en_disco() { ls "$PLUGINS_DIR"/*.nasl 2>/dev/null | wc -l; }

ospd_vts_cargados() {
  [[ -r "$OSPD_LOG" ]] && grep -q "Finished loading VTs" "$OSPD_LOG"
}

configs_en_gvmd() {
  local user="${1:-${GREENBONE_USER:-admin}}" pass="${2:-${GREENBONE_PASS:-}}"
  command -v gvm-cli >/dev/null 2>&1 || { echo 0; return; }
  timeout 15 gvm-cli tls --hostname 127.0.0.1 --gmp-username "$user" \
    --gmp-password "$pass" --xml '<get_configs filter="rows=-1"/>' 2>/dev/null \
    | grep -c "<config id=" || true
}

esperar_puerto() {
  local limite="${1:-60}" i
  info "Esperando gsad en ${PORT}/tcp (máx ${limite}s) ..."
  for ((i = 0; i < limite; i++)); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 1
  done; return 1
}

levantar() {
  requiere_root start
  if ! gvm_instalado; then err "GVM no está instalado: sudo apt-get install -y gvm gvm-tools"; exit 1; fi
  if servicio_activo gvmd && servicio_activo ospd-openvas && servicio_activo gsad; then
    info "Los servicios GVM ya están corriendo (${URL})"; return 0
  fi
  if command -v lsof >/dev/null 2>&1 && lsof -Pi ":${PORT}" -sTCP:LISTEN -t >/dev/null 2>&1; then
    err "El puerto ${PORT}/tcp ya está ocupado:"; lsof -Pi ":${PORT}" -sTCP:LISTEN; exit 1
  fi
  if [[ ! -s "$PLUGINS_DIR/feed.xml" ]] && [[ -z "$(ls -A "$PLUGINS_DIR" 2>/dev/null)" ]]; then
    warn "Feed OpenVAS vacío (sin NVTs): un escaneo fallará hasta sincronizar."
    warn "Lanzando greenbone-feed-sync en background... (tarda horas la 1ª vez)"
    sudo -u _gvm greenbone-feed-sync --type all >/var/log/gvm/feed-sync.log 2>&1 &
  fi
  info "Levantando ${SERVICIOS[*]} ..."
  systemctl start notus-scanner gvmd ospd-openvas || true; sleep 3
  systemctl start gsad || true
  mkdir -p /var/run/ospd
  [[ -e /var/run/ospd/ospd-openvas.sock ]] && ln -sf /var/run/ospd/ospd-openvas.sock /var/run/ospd/ospd.sock
  if esperar_puerto 60; then
    ok "Web UI lista: ${URL}"
    ok "Usuario: admin (contraseña definida en 'setup' o 'greenbone.sh password')"
    if ! ospd_vts_cargados; then
      warn "ospd está cargando los NVTs: los escaneos quedarán en cola hasta que termine."
    fi
  else
    warn "gvmd sigue inicializando (primera vez puede tardar minutos); reintentá 'greenbone.sh status'"
  fi
}

detener() {
  requiere_root stop
  if ! gvm_instalado; then err "GVM no está instalado"; exit 1; fi
  if sync_en_curso; then
    err "Hay una sincronización de feed en curso (greenbone-feed-sync/rsync/gvmd --rebuild)."
    err "Detener los servicios ahora puede CORROMPER la base de datos de NVTs."
    err "Esperá a que termine (controlalo con 'greenbone.sh status') o matá el sync manualmente si sabés lo que hacés."
    exit 1
  fi
  info "Deteniendo ${SERVICIOS[*]} ..."
  systemctl stop "${SERVICIOS[@]}" 2>/dev/null
  ok "Servicios detenidos (siguen deshabilitados en el arranque del sistema)"
}

estado() {
  printf '%s=== ESTADO DE SERVICIOS GVM ===%s\n' "$CIAN" "$RESET"
  local sv
  for sv in "${SERVICIOS[@]}"; do
    if servicio_activo "$sv"; then
      printf '  %-16s %s\n' "$sv" "${VERDE}activo${RESET}"
    elif systemctl is-enabled --quiet "$sv" 2>/dev/null; then
      printf '  %-16s %s\n' "$sv" "${AMAR}parado pero HABILITADO en boot${RESET}"
    else
      printf '  %-16s %s\n' "$sv" "${ROJO}parado (disabled)${RESET}"
    fi
  done
  printf '\n'
  if servicio_activo gsad; then ok "Web UI disponible en ${URL}"
  else info "Web UI apagada: sudo $0 start"; fi
  printf '\n'
  printf '%s=== FEED ===%s\n' "$CIAN" "$RESET"
  local nvts
  nvts=$(nvts_en_disco)
  printf '  NVTs en disco            : %s\n' "$nvts"
  if (( nvts == 0 )); then
    warn "Feed sin descargar: corré 'sudo $0 feed-update'"
  fi
  if ospd_vts_cargados; then
    ok "ospd: VTs cargados en caché"
  elif servicio_activo ospd-openvas; then
    warn "ospd: cargando VTs (los escaneos esperan en cola)"
  fi
  if [[ -r "$FEED_LOG" ]] && tail -100 "$FEED_LOG" | grep -qE "Updating (CPEs|data from feed)"; then
    warn "gvmd: importando feed a la BD (SCAP/CPEs/configs) — el wizard 'Quick first scan'"
    warn "      falla hasta que termine. Monitoreá: $0 wait-ready  o  $0 logs"
  fi
  printf '\n'
  if sync_en_curso; then
    warn "SINCRONIZACIÓN DE FEED EN CURSO: NO detengas los servicios hasta que termine"
    warn "(puede tardar horas en la primera descarga; los NVTs se cargan al final)"
    printf '\n'
  fi
  systemctl --no-pager -l status "${SERVICIOS[@]}" 2>/dev/null | grep -E "●|Active:" | sed 's/^ */  /'
}

reiniciar() {
  requiere_root restart
  if sync_en_curso; then
    err "Hay una sincronización de feed en curso: no se puede reiniciar sin corromper la BD de NVTs."
    err "Esperá a que termine (controlá con 'greenbone.sh status')."
    exit 1
  fi
  systemctl stop "${SERVICIOS[@]}" 2>/dev/null; sleep 2; levantar
}

feed_update() {
  requiere_root feed-update
  if sync_en_curso; then
    err "Ya hay una sincronización de feed en curso: no lanzo otra en paralelo."
    exit 1
  fi
  info "Sincronizando feeds (NVT/SCAP/CERT)... puede tardar horas la primera vez"
  greenbone-feed-sync --type all
  ok "Feed actualizado"
  info "Los NVTs se cargan en gvmd al terminar; monitoreá con 'greenbone.sh status'"
}

setup() {
  requiere_root setup
  warn "gvm-setup: crea la BD de gvmd, el usuario admin (password aleatoria impresa al final)"
  warn "y sincroniza todos los feeds. La PRIMERA VEZ puede tardar HORAS."
  gvm-setup
  ok "Setup completo. Anotá la contraseña admin mostrada arriba (o cambiala con '$0 password')."
  info "Siguiente paso:  sudo $0 start"
  info "Luego:           sudo $0 wait-ready   (espera a que el wizard web funcione)"
}

wait_ready() {
  requiere_root wait-ready
  local mins="${1:-30}"
  local user="${2:-${GREENBONE_USER:-admin}}" pass="${3:-${GREENBONE_PASS:-}}"
  if ! command -v gvm-cli >/dev/null 2>&1; then
    err "gvm-cli no está instalado (viene con gvm-tools): sudo apt-get install -y gvm-tools"
    exit 1
  fi
  if [[ -z "$pass" ]]; then
    err "Falta la contraseña GMP. Usá:"
    err "  GREENBONE_PASS='...' sudo $0 wait-ready [minutos] [usuario] [password]"
    err "  o bien:  sudo $0 wait-ready ${mins:-30} admin 'TU_PASSWORD'"
    exit 1
  fi
  if ! servicio_activo gvmd; then
    err "gvmd no está corriendo: sudo $0 start"
    exit 1
  fi
  local limite=$((mins * 2)) i n
  info "Esperando import de configs en gvmd (máx ${mins} min)..."
  for ((i = 0; i < limite; i++)); do
    n=$(configs_en_gvmd "$user" "$pass")
    if (( n > 0 )); then
      ok "Configs importados en gvmd: $n — el wizard 'Quick first scan' ya funciona"
      return 0
    fi
    info "  [$((i + 1))/${limite}] configs aún no importados (gvmd cargando SCAP/configs)... 30s más"
    sleep 30
  done
  err "Timeout tras ${mins} min: configs no disponibles todavía."
  err "Revisá el progreso real: sudo tail -50 $FEED_LOG"
  exit 1
}

wait_ready_bg() {
  require_user="${1:-admin}"; minutos="${2:-60}"; pass="${3:-}"
  if [[ -z "$pass" ]]; then err "Uso: $0 wait-ready-bg <usuario> <minutos> '<password>'"; exit 1; fi
  local log="/tmp/gvm-wait-ready-$$.log"
  setsid bash "$0" wait-ready "$minutos" "$require_user" "$pass" </dev/null >"$log" 2>&1 &
  disown 2>/dev/null || true
  ok "wait-ready corriendo en background (PID $!)"
  ok "Log: $log"
  info "Monitoreá con: tail -f $log"
  info "O verificar si terminó: cat $log | tail -5"
}

ver_logs() {
  warn "Mostrando gvmd.log y ospd-openvas.log (Ctrl+C para salir)"
  [[ -r "$FEED_LOG" ]] || { err "No puedo leer $FEED_LOG (usá sudo)"; exit 1; }
  tail -f "$FEED_LOG" "$OSPD_LOG"
}

cambiar_password() {
  local req_user="${1:-}" nueva="${2:-}"
  if [[ -z "$req_user" || -z "$nueva" ]]; then err "Uso: sudo $0 password <usuario> <nueva>"; exit 1; fi
  requiere_root password
  sudo -u _gvm gvmd --user="$req_user" --new-password="$nueva"
  ok "Contraseña actualizada para '$req_user'"
}

case "${1:-}" in
  start)        levantar ;;
  stop)         detener ;;
  restart)      reiniciar ;;
  status)       estado ;;
  setup)        setup ;;
  wait-ready)   shift; wait_ready "$@" ;;
  wait-ready-bg) shift; wait_ready_bg "$@" ;;
  feed-update)  feed_update ;;
  password)     shift; cambiar_password "$@" ;;
  logs)         ver_logs ;;
  -h|--help|"") sed -n '2,26p' "$0" ;;
  *) err "Acción desconocida: '$1' (usa start|stop|restart|status|setup|wait-ready|feed-update|password|logs)"; exit 1 ;;
esac
GREENBONE_EOF
    fi
    # Política por defecto: los servicios GVM NO deben arrancar con el sistema
    # (consumen RAM/CPU y mantienen gvmd y ospd abiertos). Quedan siempre
    # deshabilitados; el operador los levanta con greenbone.sh start.
    local sv
    for sv in gvmd ospd-openvas gsad notus-scanner; do
      if systemctl is-enabled --quiet "$sv" 2>/dev/null; then
        systemctl disable "$sv" >/dev/null 2>&1 || true
        info "Servicio '$sv' deshabilitado en el arranque (se levanta solo con greenbone.sh start)"
      fi
      systemctl stop "$sv" >/dev/null 2>&1 || true
    done
  fi
  # Guard: copias pip --user de sqlalchemy/impacket eclipsan a las del apt y
  # rompen NetExec. Ya purgadas al inicio de instalar_herramientas (línea ~1120);
  # aquí solo los consumidores ligeros (node/npm), sin re-purga redundante.
  # Node.js/npm: requisito para chrome-devtools-mcp (MCP de Chrome DevTools).
  # Se necesita Node >= 22; si no hay node o es viejo se instala vía NodeSource.
  local node_v
  node_v=$(node -v 2>/dev/null | tr -d 'v' | cut -d. -f1)
  # node presente pero parseo vacío/no-numérico (set -u + (( )) fallaba feo).
  [[ "$node_v" =~ ^[0-9]+$ ]] || node_v=0
  if command -v node >/dev/null 2>&1 && (( node_v >= 22 )); then
    info "Node.js ya instalado: $("node" -v)"
  elif (( EUID == 0 )); then
    # Pipefail en el hijo para que un curl fallido no enmascare el rc 0 de
    # `bash -` con stdin vacío. Intentar NodeSource SOLO si hay red real; en
    # ARM/Kali con DNS NAT-vmware roto el setup_22.x tarda minutos y termina
    # en fallback (peor aún: ambos corren si set -e no aísla la rama). Con
    # _gate_red cortamos antes y vamos directo al apt del sistema, que es
    # nativo ARM y rápido.
    if [[ "$KDSIO_RED" != "ok" ]]; then
      aviso "Sin red: salto NodeSource, instalando nodejs del repo del sistema"
      ejecutar "Instalando Node.js (apt del sistema, sin NodeSource)" \
        apt-get install -y -qq --no-install-recommends nodejs npm || true
    elif ejecutar "Instalando Node.js 22 (NodeSource)" bash -c '
        set -e -o pipefail
        curl -fsSL --retry 3 --max-time 30 https://deb.nodesource.com/setup_22.x | bash -
        apt-get install -y -qq --no-install-recommends nodejs'; then
      :
    else
      aviso "Falló NodeSource; intentando con nodejs del repo del sistema como fallback"
      # Re-chequeo: si node quedó >=22 por la corrida de NodeSource parcial,
      # NO re-instalar (causa del atasco en re-ejecuciones en ARM).
      local node_v2
      node_v2=$(node -v 2>/dev/null | tr -d 'v' | cut -d. -f1)
      [[ "$node_v2" =~ ^[0-9]+$ ]] || node_v2=0
      if (( node_v2 >= 22 )); then
        info "Node.js funcional tras NodeSource parcial (v$node_v2): no re-instalo"
      else
        ejecutar "Instalando Node.js (fallback apt)" \
          apt-get install -y -qq --no-install-recommends nodejs npm || true
      fi
    fi
  else
    aviso "Node.js no está instalado y requiere root: corré 'sudo $0 --herramientas' (o sudo $0) si lo necesitás."
  fi
  # chrome-devtools-mcp: servidor MCP de Chrome DevTools (se instala vía npm global).
  if command -v chrome-devtools-mcp >/dev/null 2>&1; then
    info "chrome-devtools-mcp ya está instalado ($(chrome-devtools-mcp --version 2>/dev/null | head -1))"
  elif command -v npm >/dev/null 2>&1; then
    # Sin red → saltar (no aporta nada offline y bloquea la corrida).
    if [[ "$KDSIO_RED" != "ok" ]]; then
      aviso "Sin red: chrome-devtools-mcp no se instaló"
    else
      # Flags de rendimiento en ARM (npm install por defecto baja ~50MB de
      # tarballs por re-instalación si la caché no tiene los sha512):
      # --prefer-offline usa caché primero, --no-audit evita el hit a
      # registry.npmjs.org/-/npm/v1/security, --no-fund evita metadata extra.
      ejecutar "Instalando chrome-devtools-mcp (npm global)" \
        npm install -g --prefer-offline --no-audit --no-fund chrome-devtools-mcp
    fi
  else
    aviso "npm no está disponible: chrome-devtools-mcp no se instaló"
  fi
  # chrome-devtools-mcp espera Chrome en /opt/google/chrome/chrome. En Kali hay
  # Chromium (que el paquete npm lanza con --remote-debugging-pipe de forma
  # equivalente). _resolver_chromium_bin es la fuente única de verdad (DRY),
  # compartida con el parche de Burp UserConfig.json.
  if [[ -e "/opt/google/chrome/chrome" ]]; then
    info "google-chrome ya presente en /opt/google/chrome/chrome"
  else
    local chromium_bin
    chromium_bin="$(_resolver_chromium_bin)"
    if [[ -n "$chromium_bin" && "$chromium_bin" != "/opt/google/chrome/chrome" ]]; then
      if (( EUID == 0 )); then
        ejecutar "Enlazando $chromium_bin a /opt/google/chrome/chrome" \
          bash -c "mkdir -p /opt/google/chrome && ln -sf '$chromium_bin' '/opt/google/chrome/chrome'"
      else
        aviso "No se pudo enlazar Chromium a /opt/google/chrome/chrome (falta root)"
      fi
    else
      aviso "No se encontró Chromium/Chrome para el MCP de chrome-devtools"
    fi
  fi
  # computer-use-linux: MCP (stdio) que automatiza el escritorio Linux real
  # (AT-SPI, screenshots vía portal, clicks/teclado vía ydotool/xdotool,
  # listado/foco de ventanas). Binario Rust instalado vía npm wrapper.
  # Deps X11/XFCE: xdotool (input) + wmctrl/xprop (ventanas EWMH) + at-spi2-core.
  local deps_cul=()
  command -v xdotool >/dev/null 2>&1 || deps_cul+=(xdotool)
  command -v wmctrl  >/dev/null 2>&1 || deps_cul+=(wmctrl)
  command -v xprop   >/dev/null 2>&1 || deps_cul+=(xprop)
  dpkg -s at-spi2-core >/dev/null 2>&1 || deps_cul+=(at-spi2-core)
  if ((${#deps_cul[@]})); then
    if (( EUID == 0 )); then
      if [[ "$KDSIO_RED" == "ok" ]]; then
        ejecutar "Instalando dependencias de computer-use-linux (${deps_cul[*]})" \
          apt-get install -y -qq --no-install-recommends "${deps_cul[@]}"
      else
        aviso "Sin red: dependencias de computer-use-linux no instaladas (${deps_cul[*]})"
      fi
    else
      aviso "Sin root: faltan dependencias de computer-use-linux (${deps_cul[*]}) — sudo $0 --herramientas"
    fi
  fi
  if command -v "$CUL_BIN" >/dev/null 2>&1; then
    info "$CUL_BIN ya está instalado ($("$CUL_BIN" --version 2>/dev/null | head -1))"
  elif command -v npm >/dev/null 2>&1; then
    if [[ "$KDSIO_RED" != "ok" ]]; then
      aviso "Sin red: computer-use-linux no se instaló"
    else
      ejecutar "Instalando $CUL_NPM_PKG (npm global; binario Rust precompilado)" \
        npm install -g --prefer-offline --no-audit --no-fund "$CUL_NPM_PKG"
    fi
  else
    aviso "npm no está disponible: computer-use-linux no se instaló"
  fi
  # Garantizar que el binario esté en el PATH del usuario aunque npm tenga un
  # prefijo no estándar (ej. ~/.npm-global): symlink idempotente en
  # ~/.local/bin (el mismo PATH donde vive ~/.opencode/bin).
  local cul_encontrado
  cul_encontrado="$(command -v "$CUL_BIN" 2>/dev/null || true)"
  if [[ -z "$cul_encontrado" ]]; then
    cul_encontrado="$(find "${npm_config_prefix:-/usr}/lib/node_modules" \
      -type f -path '*computer-use-linux/npm/bin/computer-use-linux.js' 2>/dev/null | head -1)"
  fi
  if [[ -n "$cul_encontrado" && ! -e "$HOME_REAL/.local/bin/$CUL_BIN" ]]; then
    if (( EUID == 0 )); then
      ejecutar "Enlazando $CUL_BIN en $HOME_REAL/.local/bin (PATH de usuario)" \
        bash -c "mkdir -p '$HOME_REAL/.local/bin' && ln -sf '$cul_encontrado' '$HOME_REAL/.local/bin/$CUL_BIN' && chown -h '$USUARIO_REAL':'$(id -gn "$USUARIO_REAL")' '$HOME_REAL/.local/bin/$CUL_BIN'"
    else
      ejecutar "Enlazando $CUL_BIN en $HOME_REAL/.local/bin (PATH de usuario)" \
        bash -c "mkdir -p '$HOME_REAL/.local/bin' && ln -sf '$cul_encontrado' '$HOME_REAL/.local/bin/$CUL_BIN'"
    fi
  fi
  # AT-SPI + doctor: el MCP necesita el bus de accesibilidad habilitado para
  # exponer árboles semánticos (get_app_state/click por selector). COMO
  # USUARIO (gsettings/dconf son por-usuario: como root tocaría el dconf de
  # root y el setup sería no-op para quien usa el escritorio). Reutiliza la
  # ruta resuelta de cul_encontrado porque `command -v` de root puede no ver
  # el binario si vive en un prefijo npm del usuario (~/.npm-global).
  local cul_cmd="${cul_encontrado:-$(command -v "$CUL_BIN" 2>/dev/null || true)}"
  if [[ -n "$cul_cmd" ]]; then
    ejecutar "Habilitando AT-SPI (computer-use-linux setup) y verificando con doctor" \
      _como_usuario env HOME="$HOME_REAL" \
        bash -c "'$cul_cmd' setup >/dev/null 2>&1; '$cul_cmd' doctor"
  fi
  # opencode: CLI de código asistida por IA (se instala con el usuario real).
  # El instalador oficial instala en ~/.opencode/bin, por lo que se ejecuta
  # siempre con el usuario real ($USUARIO_REAL), nunca en root.
  local oc_bin="$HOME_REAL/.opencode/bin"
  local oc="$oc_bin/opencode"
  if [[ -x "$oc" ]]; then
    info "opencode ya está instalado para $USUARIO_REAL ($("$oc" --version 2>/dev/null | head -1))"
  elif command -v curl >/dev/null 2>&1; then
    ejecutar "Instalando opencode (CLI) para $USUARIO_REAL" \
      _como_usuario env HOME="$HOME_REAL" \
        bash -c 'set -o pipefail; curl -fsSL --max-time 120 https://opencode.ai/install | bash' || true
    if [[ -x "$oc" ]]; then
      _dueno "$oc_bin"
      info "opencode instalado para $USUARIO_REAL ($(_como_usuario env HOME="$HOME_REAL" "$oc" --version 2>/dev/null | head -1))"
    else
      aviso "opencode no quedó instalado: revisá la conexión a opencode.ai"
    fi
  else
    aviso "curl no está disponible: opencode no se instaló"
  fi
  # Asegurar ~/.opencode/bin en el PATH del usuario (crea ~/.bashrc si falta).
  local oc_bashrc="$HOME_REAL/.bashrc"
  if [[ -x "$oc" ]]; then
    _asegurar_path_bashrc "$oc_bashrc" '.opencode/bin' '$HOME/.opencode/bin' 'añadir opencode al PATH'
  fi
  # Icono oficial de opencode (para el launcher del panel). Se descarga junto a
  # la instalación para que quede en el home del usuario pase o no por la fase de
  # identidad; el launcher del panel lo crea _marca_usuario cuando hay sesión.
  if [[ -x "$oc" ]]; then
    _icono_opencode
  fi
  # OCLoop (https://github.com/dragonjar/ocloop): harness de bucles que
  # orquesta opencode para ejecutar un PLAN.md tarea a tarea, sin
  # supervisión (sobrevive rate limits, sleeps y crashes). Requiere Bun
  # (runtime) y opencode ya funcional. Todo como USUARIO real: Bun vive en
  # ~/.bun y el repo en ~/Herramientas/ocloop; el binario `ocloop` queda
  # en ~/.local/bin (envoltorio bash que invoca bun con la ruta absoluta,
  # así no depende del shebang ni del PATH de bun).
  local bun_bin="$HOME_REAL/.bun/bin"
  local bun="$bun_bin/bun"
  if [[ -x "$bun" ]]; then
    info "Bun ya está instalado para $USUARIO_REAL ($("$bun" --version 2>/dev/null | head -1))"
  elif command -v curl >/dev/null 2>&1; then
    if [[ "$KDSIO_RED" == "ok" ]]; then
      ejecutar "Instalando Bun (runtime de OCLoop) para $USUARIO_REAL" \
        _como_usuario env HOME="$HOME_REAL" \
          bash -c 'set -o pipefail; curl -fsSL --max-time 180 https://bun.sh/install | bash' || true
      [[ -x "$bun" ]] && _dueno "$HOME_REAL/.bun"
    else
      aviso "Sin red: Bun no se instaló (OCLoop lo requiere)"
    fi
  else
    aviso "curl no está disponible: Bun no se instaló (OCLoop lo requiere)"
  fi
  if [[ -x "$bun" ]]; then
    _asegurar_path_bashrc "$HOME_REAL/.bashrc" '.bun/bin' '$HOME/.bun/bin' 'añadir bun al PATH'
    local ocloop_dir="$herramientas/ocloop"
    if _git_clonar "$ocloop_dir" "https://github.com/dragonjar/ocloop" "OCLoop (harness de bucles para opencode)"; then
      if [[ -f "$ocloop_dir/dist/index.js" && -d "$ocloop_dir/node_modules" ]]; then
        info "OCLoop ya está construido en $ocloop_dir"
      else
        ejecutar "Compilando OCLoop (bun install + bun run build)" \
          _como_usuario env HOME="$HOME_REAL" PATH="$bun_bin:/usr/local/bin:/usr/bin:/bin" \
            bash -c "cd '$ocloop_dir' && '$bun' install --frozen-lockfile && '$bun' run build"
      fi
      if [[ -f "$ocloop_dir/dist/index.js" ]]; then
        # Se reescribe SIEMPRE (no solo si falta): si bun se actualizó de
        # ruta o el repo se re-clonó, un wrapper viejo quedaría huérfano.
        ejecutar "Enlazando ocloop en $HOME_REAL/.local/bin" \
          bash -c "mkdir -p '$HOME_REAL/.local/bin' && printf '#!/usr/bin/env bash\nexec %q %q \"\$@\"\n' '$bun' '$ocloop_dir/dist/index.js' > '$HOME_REAL/.local/bin/ocloop' && chmod +x '$HOME_REAL/.local/bin/ocloop'"
        _dueno "$HOME_REAL/.local/bin/ocloop"
        info "OCLoop listo: ejecutá 'ocloop --create-plan' y luego 'ocloop' (requiere opencode configurado)"
      else
        aviso "OCLoop no se compiló: revisá $REGISTRO"
      fi
    else
      aviso "OCLoop no se pudo clonar (¿sin red o sin git?)"
    fi
  fi
  # PIPX_BIN_DIR apunta a ~/.local/bin y a veces no está en el PATH del usuario.
  local px_bin="$HOME_REAL/.local/bin"
  local px_home="$HOME_REAL/.local/pipx"
  local bb="$px_bin/bbot"
  if [[ -x "$bb" ]]; then
    info "bbot ya está instalado para $USUARIO_REAL ($("$bb" --version 2>/dev/null | tail -1))"
  else
    ejecutar "Instalando bbot vía pipx (usuario $USUARIO_REAL)" \
      _como_usuario env PIPX_BIN_DIR="$px_bin" PIPX_HOME="$px_home" \
        pipx install bbot
  fi
  if [[ -x "$bb" ]]; then
    # Confirmar que bbot corre en el entorno del usuario (sin instalar nada en root:
    # las dependencias de sistema se instalan bajo demanda en el primer escaneo,
    # usando el sudo del propio usuario).
    local bbotv
    bbotv=$(_como_usuario "$bb" --version 2>/dev/null | tail -1)
    info "bbot listo para $USUARIO_REAL ($bbotv); sus dependencias de sistema se instalan en el primer escaneo con su sudo"
  else
    info "bbot no quedó instalado: se omite la verificación"
  fi
  # trivy: escáner de vulnerabilidades en dependencias (laboratorio
  # SUPPLY-CHAIN del manual: `trivy fs /var/www/html/SUPPLY-CHAIN/`). Cruza
  # composer.lock/package-lock.json/requirements.txt con su DB de CVEs.
  # No está en apt: binario oficial de GitHub releases por arquitectura.
  local tv_bin="/usr/local/bin/trivy"
  local tv_asset
  case "$KDSIO_ARCH" in
    amd64) tv_asset="Linux-64bit.tar.gz" ;;
    arm64) tv_asset="Linux-ARM64.tar.gz" ;;
    armhf) tv_asset="Linux-ARM.tar.gz" ;;
    i386)  tv_asset="Linux-32bit.tar.gz" ;;
    *)     tv_asset="" ;;
  esac
  if [[ -x "$tv_bin" ]]; then
    info "trivy ya está instalado ($("$tv_bin" --version 2>/dev/null | head -1))"
  elif [[ -z "$tv_asset" ]]; then
    aviso "trivy sin release para '$KDSIO_ARCH': omitido"
  elif (( EUID == 0 )); then
    if ! _gate_red "instalar trivy" || ! _gate_disco 128 "instalar trivy"; then
      :
    else
      # Consultar API de GitHub por la versión (el asset lleva el número de
      # versión en el nombre: no hay URL /latest/download fija). Mismo patrón
      # que gospider/findomain. Fallback vacío → aviso limpio.
      local tv_url
      tv_url=$(curl -fsSL --retry 2 --max-time 30 https://api.github.com/repos/aquasecurity/trivy/releases/latest 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    ver = d.get('tag_name', '').lstrip('v')
    suffix = '${tv_asset}'
    if ver and suffix:
        print('https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_%s' % (ver, ver, suffix))
except Exception:
    pass
" 2>/dev/null)
      if [[ -n "$tv_url" ]]; then
        local tv_tmp
        tv_tmp=$(mktemp -d /tmp/kdsio-trivy.XXXXXX)
        ejecutar "Descargando e instalando trivy ($KDSIO_ARCH)" bash -c "
          curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --max-time 300 -o '$tv_tmp/trivy.tar.gz' '$tv_url' &&
          tar -C '$tv_tmp' -xzf '$tv_tmp/trivy.tar.gz' trivy &&
          install -m755 '$tv_tmp/trivy' '$tv_bin'; rc=\$?; rm -rf '$tv_tmp'; exit \$rc"
        if [[ -x "$tv_bin" ]]; then
          info "trivy instalado ($("$tv_bin" --version 2>/dev/null | head -1))"
        else
          aviso "trivy no quedó instalado: revisá el registro"
        fi
      else
        aviso "No se pudo resolver el asset de trivy para '$KDSIO_ARCH': omitido"
      fi
    fi
  else
    aviso "trivy requiere root (/usr/local/bin): corré 'sudo $0 --herramientas'"
  fi
  # DB de vulnerabilidades de trivy: pre-carga/actualización explícita
  # (~112MB OCI vía mirror.gcr.io; extrae ~1.3GB en ~/.cache/trivy). COMO
  # USUARIO REAL: la DB debe vivir en el cache de quien escanea (si la
  # bajara root, el primer 'trivy fs' del estudiante la volvería a bajar a
  # su home). Idempotente: si la DB tiene <24h trivy sale al instante; si
  # no, descarga y reemplaza atómicamente. Java DB omitida: el lab
  # SUPPLY-CHAIN cruza composer.lock/package-lock/requirements.txt, no jars.
  if [[ -x "$tv_bin" ]] && _gate_red "actualizar DB de trivy" \
     && _gate_disco 2048 "actualizar DB de trivy"; then
    # Blindaje de propiedad: si un uso previo de trivy como root dejó
    # ~/.cache/trivy con dueño root, el usuario no podría escribir su DB.
    # _dueno solo actúa con root; sin él es no-op (y trivy avisará igual).
    [[ -e "$HOME_REAL/.cache/trivy" ]] && _dueno "$HOME_REAL/.cache/trivy"
    ejecutar "Actualizando DB de vulnerabilidades de trivy (como $USUARIO_REAL)" \
      _como_usuario env HOME="$HOME_REAL" \
        trivy image --download-db-only \
      || aviso "trivy no pudo actualizar su DB: revisá el registro (el primer escaneo la bajará solo)"
  fi
  # pip-audit: auditor de CVEs en paquetes Python (laboratorio SUPPLY-CHAIN:
  # `pip-audit -r requirements.txt` + uso en CI con GitHub Actions).
  # pipx (aislado, mismo patrón que bbot) con sus vars ya definidas arriba.
  local pa_bin="$px_bin/pip-audit"
  if [[ -x "$pa_bin" ]]; then
    info "pip-audit ya está instalado ($("$pa_bin" --version 2>/dev/null | tail -1))"
  elif command -v pipx >/dev/null 2>&1; then
    ejecutar "Instalando pip-audit (pipx para $USUARIO_REAL)" \
      _como_usuario env PIPX_BIN_DIR="$px_bin" PIPX_HOME="$px_home" \
        pipx install pip-audit || true
    if [[ -x "$pa_bin" ]]; then
      info "pip-audit listo: usar 'pip-audit -r requirements.txt' (lab SUPPLY-CHAIN)"
    else
      aviso "pip-audit no quedó instalado: revisá el registro"
    fi
  else
    aviso "pipx no está disponible: pip-audit no se instaló (corré 'sudo $0 --herramientas')"
  fi
  # Garantizar ~/.local/bin en el PATH del usuario (crea ~/.bashrc si falta).
  local bashrc="$HOME_REAL/.bashrc"
  _asegurar_path_bashrc "$bashrc" '.local/bin' '$HOME/.local/bin' 'añadir binarios de pipx al PATH'
  # Carpeta Herramientas en el home del usuario con el contenido de DragonJAR.
  # Todo en el entorno del usuario ($USUARIO_REAL), nunca en root.
  local herramientas="$HOME_REAL/Herramientas"
  _descargar_script "$herramientas/eValidator.py" 're:api/v1/verify' \
    'eValidator.py' 'eValidator.py'
  _descargar_script "$herramientas/Cateyes.jpg" '' \
    'Cateyes.jpg' 'Cateyes.jpg'
  _descargar_script "$herramientas/wayback_subdomains.sh" 're:#!/usr/bin/env bash' \
    'wayback_subdomains.sh' 'wayback_subdomains.sh'
  _descargar_script "$herramientas/NmapDataExtractor.py" 're:NmapDataExtractor' \
    'NmapDataExtractor/NmapDataExtractor.py' 'NmapDataExtractor.py'
  _descargar_script "$herramientas/prueba.xml" 're:nmaprun' \
    'NmapDataExtractor/prueba.xml' 'prueba.xml (Nmap)'
  _descargar_script "$herramientas/acccheck.py" 're:impacket' \
    'acccheck.py' 'acccheck.py (SMB password audit)' 'DragonJAR/Scripts'
  _descargar_script "$herramientas/badpdf.py" 're:import' \
    'badpdf.py' 'badpdf.py (Net-NTLM Hash via Bad-PDF)' 'deepzec/Bad-Pdf'
  # BackupDetective (DragonJAR): extensión Burp en Jython que busca copias de
  # seguridad de un sitio (backups indexables, .bak/.old/~/ etc. vía Wayback
  # y archives). Carga en Burp → Extensions → Add → Python.
  _descargar_script "$herramientas/BackupDetective.py" 're:IBurpExtender' \
    'ChatGPT/BackupDetective.py' 'BackupDetective.py (Burp ext: backups via Wayback)'
  # nmap-parse-output (ernw): convierte/manipula XML de Nmap con XSLT.
  # Se clona porque el script bash depende del directorio nmap-parse-output-xslt/
  # que viaja junto al ejecutable; necesita además xmllint (libxml2-utils) para
  # funcionar (apt ya lo trae en Kali).
  local npo_dir="$herramientas/nmap-parse-output"
  if [[ -x "$npo_dir/nmap-parse-output" ]]; then
    info "nmap-parse-output (ernw) ya está en $npo_dir"
  else
    if (( EUID == 0 )); then
      ejecutar "Instalando libxml2-utils (xmllint) para nmap-parse-output" \
        apt-get install -y -qq --no-install-recommends libxml2-utils
    fi
    _git_clonar "$npo_dir" "https://github.com/ernw/nmap-parse-output" "nmap-parse-output (ernw)"
    if [[ -f "$npo_dir/nmap-parse-output" ]]; then
      chmod +x "$npo_dir/nmap-parse-output" "$npo_dir/_nmap-parse-output" 2>/dev/null || true
      _dueno "$npo_dir"
    fi
  fi
  if [[ -f "$herramientas/eValidator.py" ]]; then
    # Dependencias de eValidator.py: solo la librería externa 'requests'.
    # apt-first (python3-requests): una copia pip --user sombrearía la del
    # sistema y puede romper herramientas del apt (misma clase de bug que
    # NetExec+sqlalchemy). pip --user queda como fallback sin root.
    if _como_usuario env HOME="$HOME_REAL" python3 -c "import requests" >/dev/null 2>&1; then
      info "Dependencia 'requests' (eValidator.py) ya disponible"
    elif (( EUID == 0 )); then
      ejecutar "Instalando python3-requests (apt, para eValidator.py)" \
        apt-get install -y -qq --no-install-recommends python3-requests
    else
      ejecutar "Instalando dependencia Python 'requests' (eValidator.py, pip --user)" \
        _como_usuario env HOME="$HOME_REAL" \
          python3 -m pip install --user --break-system-packages requests
    fi
  fi
  # Enlaces web en ~/Herramientas (Type=Link): abren el navegador al hacer
  # doble clic. Helper genérico para no duplicar la lógica.
  _enlace_web "$herramientas/EXIF-READER" "EXIF-READER" "https://linangdata.com/exif-reader/" web-browser
  _enlace_web "$herramientas/RECON" "RECON" "https://www.dragonjar.org/RECON/" web-browser
  _enlace_web "$herramientas/OSINT" "OSINT" "https://www.dragonjar.org/OSINT/" web-browser
  _enlace_web "$herramientas/SCOPE" "SCOPE" "https://contenido.dragonjar.org/pentesting-scope-designer-page" web-browser
  # acccheck.py: auditoria SMB sin smbclient; usa impacket como única
  # dependencia. El propio script la autoinstala si falta (vía pip), pero
  # preinstalarla ahorra tiempo en la primera corrida.
  # apt-first (python3-impacket): NetExec usa el impacket del sistema; una
  # copia pip --user en ~/.local lo sombrea y puede romper nxc (protocolos
  # compilados contra la versión del apt). pip --user solo como fallback
  # sin root, y _purgar_sombra_pip impacket la retiraría en la siguiente
  # corrida con root de todos modos.
  if [[ -f "$herramientas/acccheck.py" ]]; then
    if _como_usuario env HOME="$HOME_REAL" python3 -c "import impacket" >/dev/null 2>&1; then
      info "Dependencia 'impacket' (acccheck.py) ya disponible"
    elif (( EUID == 0 )); then
      ejecutar "Instalando python3-impacket (apt, para acccheck.py)" \
        apt-get install -y -qq --no-install-recommends python3-impacket
    else
      ejecutar "Instalando dependencia Python 'impacket' (acccheck.py, pip --user)" \
        _como_usuario env HOME="$HOME_REAL" \
          python3 -m pip install --user --break-system-packages impacket
    fi
  fi
  # cupp: generador de diccionarios de contraseñas (Common User Password Profiler).
  # Se clona en ~/Herramientas/cupp; solo usa la biblioteca estándar de Python 3.
  local cupp_dir="$herramientas/cupp"
  if [[ -x "$cupp_dir/cupp.py" ]]; then
    info "cupp ya está instalado en $cupp_dir"
  else
    _git_clonar "$cupp_dir" "https://github.com/mebus/cupp" "cupp"
  fi
  # apache-scalp (Scalp!/Anathema): analizador de logs de acceso Apache/Nginx
  # que detecta ataques web (SQLi, XSS, LFI, SSRF, log4j, etc.) con las
  # firmas de PHPIDS + reglas modernas. Repo en ~/Herramientas/apache-scalp.
  # Dependencias (pyproject: solo 'regex'):
  #   apt-first  : python3-regex (Kali la trae; nunca pip --user por encima
  #                del sistema, misma clase de bug que NetExec+sqlalchemy).
  #   CLI 'scalp': pipx con el paquete del repo (venv aislado con su 'regex';
  #                entry point del pyproject). El repo clonado sigue siendo
  #                utilizable a mano con python3 scalp.py ...
  local as_dir="$herramientas/apache-scalp"
  if [[ -f "$as_dir/scalp.py" ]]; then
    info "apache-scalp ya está clonado en $as_dir"
  else
    _git_clonar "$as_dir" "https://github.com/DragonJAR/apache-scalp" "apache-scalp (Scalp!/Anathema)"
  fi
  if [[ -f "$as_dir/scalp.py" ]]; then
    if _como_usuario env HOME="$HOME_REAL" python3 -c "import regex" >/dev/null 2>&1; then
      info "Dependencia 'regex' (apache-scalp) ya disponible en el sistema"
    elif (( EUID == 0 )); then
      ejecutar "Instalando python3-regex (apt, para apache-scalp)" \
        apt-get install -y -qq --no-install-recommends python3-regex
    else
      ejecutar "Instalando dependencia Python 'regex' (apache-scalp, pip --user)" \
        _como_usuario env HOME="$HOME_REAL" \
          python3 -m pip install --user --break-system-packages regex || true
    fi
    if command -v pipx >/dev/null 2>&1; then
      if [[ -x "$px_bin/scalp" ]]; then
        info "scalp (CLI) ya está instalado via pipx"
      else
        ejecutar "Instalando scalp CLI (pipx, desde el repo apache-scalp)" \
          _como_usuario env PIPX_BIN_DIR="$px_bin" PIPX_HOME="$px_home" \
            pipx install --system-site-packages "$as_dir" || true
      fi
      if [[ -x "$px_bin/scalp" ]] || command -v scalp >/dev/null 2>&1; then
        if _como_usuario env HOME="$HOME_REAL" PATH="$px_bin:$PATH" \
             scalp --version >/dev/null 2>&1; then
          info "scalp verificado: usar 'scalp' (o python3 ~/Herramientas/apache-scalp/scalp.py)"
        else
          aviso "scalp no responde tras instalación: probá 'pipx install --system-site-packages ~/Herramientas/apache-scalp'"
        fi
      else
        aviso "scalp (pipx) no quedó instalado: el repo queda usable con 'python3 scalp.py'"
      fi
    else
      aviso "pipx no está disponible: CLI 'scalp' omitido (el repo sigue usable con python3)"
    fi
  fi
  # ghauri: SQLi detection/exploitation avanzado (Boolean, Error, Time, Stacked).
  # Se clona en ~/Herramientas/ghauri y se instala por pip editable (usuario)
  # para que el binario `ghauri` esté en ~/.local/bin sin sudo.
  local ghauri_dir="$herramientas/ghauri"
  if [[ -f "$ghauri_dir/ghauri/__init__.py" ]]; then
    info "ghauri ya está clonado en $ghauri_dir"
  else
    _git_clonar "$ghauri_dir" "https://github.com/r0oth3x49/ghauri.git" "ghauri (SQLi detection/exploitation)"
  fi
  if [[ -f "$ghauri_dir/setup.py" ]]; then
    if _como_usuario env HOME="$HOME_REAL" python3 -c "import ghauri" >/dev/null 2>&1 \
       && [[ -x "$HOME_REAL/.local/bin/ghauri" ]]; then
      info "ghauri ya está instalado (pip editable en $ghauri_dir)"
    else
      ejecutar "Instalando ghauri (pip editable para $USUARIO_REAL)" \
        _como_usuario env HOME="$HOME_REAL" \
          python3 -m pip install --user --break-system-packages -e "$ghauri_dir" || true
    fi
    # __main__.py: habilita `python3 -m ghauri` desde la raíz del repo
    # (sin él, `python -m ghauri` falla: "cannot be directly executed").
    if [[ ! -f "$ghauri_dir/ghauri/__main__.py" ]]; then
      _como_usuario bash -c "echo 'from ghauri.scripts.ghauri import main; main()' > '$ghauri_dir/ghauri/__main__.py'"
    fi
    # Smoke test: verificar que el entry point responde
    if _como_usuario env HOME="$HOME_REAL" \
         PATH="$HOME_REAL/.local/bin:$PATH" ghauri --version >/dev/null 2>&1; then
      info "ghauri verificado: usar 'ghauri' desde PATH (no 'python ghauri.py')"
    else
      aviso "ghauri no responde tras instalación: probá 'pip3 install --user --break-system-packages -e ~/Herramientas/ghauri'"
    fi
  fi
  # commix: Automated All-in-One OS Command Injection Exploitation Tool.
  # Se clona en ~/Herramientas/commix y se corre con python3 (script directo,
  # no necesita instalación pip). Se crea symlink en ~/.local/bin.
  local commix_dir="$herramientas/commix"
  if [[ -f "$commix_dir/commix.py" ]]; then
    info "commix ya está clonado en $commix_dir"
  else
    _git_clonar "$commix_dir" "https://github.com/commixproject/commix.git" "commix (OS Command Injection)"
  fi
  if [[ -f "$commix_dir/commix.py" ]]; then
    _linkear_bin_usuario "$commix_dir/commix.py" commix
    chmod +x "$commix_dir/commix.py" 2>/dev/null || true
  fi
  # git-dumper: dumpea un repositorio .git expuesto en un sitio web (HEAD,
  # index, packs y objetos). Deps: requests/bs4/dulwich/PySocks viajan por apt
  # (python3-*); requests-pkcs12 no existe en Debian → pip --user del usuario.
  # El script lo importa a nivel de módulo: sin él ni arranca.
  local gd_dir="$herramientas/git-dumper"
  if [[ -f "$gd_dir/git_dumper.py" ]]; then
    info "git-dumper ya está clonado en $gd_dir"
  else
    _git_clonar "$gd_dir" "https://github.com/arthaud/git-dumper.git" "git-dumper"
  fi
  if [[ -f "$gd_dir/git_dumper.py" ]]; then
    chmod +x "$gd_dir/git_dumper.py" 2>/dev/null || true
    _linkear_bin_usuario "$gd_dir/git_dumper.py" git-dumper
    if _como_usuario env HOME="$HOME_REAL" python3 -c "import requests, bs4, dulwich, socks, requests_pkcs12" >/dev/null 2>&1; then
      info "Dependencias de git-dumper ya disponibles"
    elif (( EUID == 0 )); then
      ejecutar "Instalando deps git-dumper (apt: requests/bs4/dulwich/socks)" \
        apt-get install -y -qq --no-install-recommends \
          python3-requests python3-bs4 python3-dulwich python3-socks
      ejecutar "Instalando requests-pkcs12 (pip --user; no está en apt)" \
        _como_usuario env HOME="$HOME_REAL" \
          python3 -m pip install --user --break-system-packages requests-pkcs12 || true
    else
      ejecutar "Instalando deps git-dumper (pip --user, sin root)" \
        _como_usuario env HOME="$HOME_REAL" \
          python3 -m pip install --user --break-system-packages -r "$gd_dir/requirements.txt" || true
    fi
    if _como_usuario env HOME="$HOME_REAL" python3 "$gd_dir/git_dumper.py" --help >/dev/null 2>&1; then
      info "git-dumper verificado: usar 'git-dumper <url> <dir>' desde PATH"
    else
      aviso "git-dumper no responde a --help: revisá deps (python3-dulwich reciente, requests-pkcs12)"
    fi
  fi
  # sippts: suite de auditoría de VoIP/SIP (Pepelux, 571★). Python con deps
  # (netifaces, requests, IPy, scapy, pyshark, websocket-client, etc).
  # Se clona en ~/Herramientas/sippts y se instala pip editable (usuario)
  # para que el binario `sippts` esté en ~/.local/bin sin sudo.
  local sippts_dir="$herramientas/sippts"
  if [[ -f "$sippts_dir/setup.py" ]]; then
    info "sippts ya está clonado en $sippts_dir"
  else
    _git_clonar "$sippts_dir" "https://github.com/Pepelux/sippts.git" "sippts (SIP/VoIP auditing)"
  fi
  if [[ -f "$sippts_dir/setup.py" ]]; then
    if command -v sippts >/dev/null 2>&1; then
      info "sippts ya está instalado ($(sippts --help 2>&1 | head -1 | cut -c1-60))"
    else
      ejecutar "Instalando sippts (pip editable para $USUARIO_REAL)" \
        _como_usuario env HOME="$HOME_REAL" \
          python3 -m pip install --user --break-system-packages -e "$sippts_dir" || true
    fi
  fi
  # x8 (Sh1Yo): Hidden parameters discovery suite (Rust). En amd64 hay
  # binarios pre-compilados (release asset); en arm64 hay que compilar desde
  # fuente con cargo. Se clona en ~/Herramientas/x8 y se enlaza en ~/.local/bin.
  local x8_dir="$herramientas/x8"
  local x8_bin="$x8_dir/target/release/x8"
  if [[ -x "$x8_bin" ]]; then
    info "x8 ya está disponible en $x8_bin"
  else
    _git_clonar "$x8_dir" "https://github.com/Sh1Yo/x8.git" "x8 (Hidden parameters discovery)"
    # Arch canónica KDSIO_ARCH (fuente única, ya sin dpkg||uname ad hoc).
    case "$KDSIO_ARCH" in
      amd64)
        # Binario pre-compilado: evitar el coste de rustup+cargo (~5 min).
        # Gate: la descarga requiere red y ~50MB libres.
        if ! _gate_red "instalar x8 (release amd64)" || ! _gate_disco 256 "instalar x8"; then
          :
        else
        # Asset upstream real (verificado v4.3.0): `x86_64-linux-x8.gz` —
        # gzip del ELF crudo, NO un tar.xz. El fallback hardcodeado a
        # `x8-x86_64-unknown-linux-musl.tar.xz` da 404. El matcher exige el
        # nombre exacto del asset para evitar capturar `x86-windown-x8.zip`.
        local x8_asset
        x8_asset=$(curl -fsSL --retry 2 --max-time 30 https://api.github.com/repos/Sh1Yo/x8/releases/latest 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for a in d.get('assets', []):
        if a.get('name', '') == 'x86_64-linux-x8.gz':
            print(a['browser_download_url']); break
except Exception:
    sys.exit(1)
" 2>/dev/null)
        x8_asset="${x8_asset:-https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-linux-x8.gz}"
        local x8_gz
        x8_gz=$(mktemp /tmp/kdsio-x8.XXXXXX.gz)
        ejecutar "Descargando x8 pre-compilado (amd64)" bash -c "
          cd '$x8_dir' && \
          curl -fsSL --retry 3 --retry-delay 5 --max-time 120 -o '$x8_gz' '$x8_asset' && \
          gunzip -f '$x8_gz' -c > '$x8_dir/x8' && \
          chmod +x '$x8_dir/x8' && mkdir -p '$x8_dir/target/release' && \
          ln -sf '$x8_dir/x8' '$x8_bin'; rc=\$?; rm -f '$x8_gz'; exit \$rc"
        if [[ -x "$x8_bin" ]]; then
            _linkear_bin_usuario "$x8_bin" x8
          _dueno "$x8_dir"
          info "x8 enlazado en ~/.local/bin (amd64 pre-compilado)"
        fi
        fi
        ;;
      arm64)
        # Sin binario pre-compilado → rustup + cargo build --release.
        # El build de Rust pega duro en RAM: con <1.5GB es OOM probable
        # (gate fail-fast antes de instalar toda la toolchain).
        if ! _gate_ram 1536 "compilar x8 (Rust)"; then
          :
        else
        if ! _como_usuario test -f "$HOME_REAL/.cargo/bin/cargo"; then
          if (( EUID == 0 )); then
            ejecutar "Instalando Rust (rustup) para $USUARIO_REAL" \
              _como_usuario bash -c 'RUSTUP_SH=$(mktemp /tmp/kdsio-rustup.XXXXXX.sh); curl -sSf --retry 3 --retry-delay 5 --max-time 120 https://sh.rustup.rs -o "$RUSTUP_SH" && sh "$RUSTUP_SH" -y --default-toolchain stable --profile minimal; rc=$?; rm -f "$RUSTUP_SH"; exit $rc'
          else
            aviso "cargo no está disponible y Rust requiere instalación como usuario:"
            aviso "corré: curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal"
          fi
        fi
        if _como_usuario test -f "$HOME_REAL/.cargo/bin/cargo"; then
          ejecutar "Compilando x8 (cargo build --release, arm64)" \
            _como_usuario env HOME="$HOME_REAL" PATH="$HOME_REAL/.cargo/bin:$PATH" \
              bash -c "cd '$x8_dir' && cargo build --release"
          if [[ -x "$x8_bin" ]]; then
          _linkear_bin_usuario "$x8_bin" x8
            info "x8 compilado + symlink en ~/.local/bin (arm64)"
          fi
        fi
        fi
        ;;
      *)
        aviso "Arquitectura '$KDSIO_ARCH' sin ruta de instalación para x8"
        ;;
    esac
  fi
  # BurpIA: extensión de Burp Suite con IA (DragonJAR). Descarga SIEMPRE la
  # última versión desde GitHub API (repos/DragonJAR/BurpIA/releases/latest).
  local burpia_jar="$herramientas/BurpIA.jar"
  if [[ -s "$burpia_jar" ]]; then
    info "BurpIA.jar ya está en ~/Herramientas"
  elif (( EUID == 0 )); then
    # La consulta a la API solo cuando hace falta descargar (antes se hacía
    # en CADA corrida aunque el .jar ya existiera).
    local burpia_api="https://api.github.com/repos/DragonJAR/BurpIA/releases/latest"
    local burpia_url
    burpia_url=$(curl -fsSL --retry 2 --max-time 30 "$burpia_api" 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for a in d.get('assets', []):
    if a.get('name', '').endswith('.jar'):
        print(a['browser_download_url'])
        break
" 2>/dev/null)
    if [[ -z "$burpia_url" ]]; then
      local rel_tag
      rel_tag=$(curl -fsSL --retry 2 --max-time 15 "https://github.com/DragonJAR/BurpIA/releases/latest" 2>/dev/null \
        | grep -oE '/DragonJAR/BurpIA/releases/download/[^"]+\.jar' | head -1)
      if [[ -n "$rel_tag" ]]; then
        burpia_url="https://github.com$rel_tag"
        info "BurpIA URL resuelta vía web fallback: $burpia_url"
      else
        aviso "No se pudo resolver el JAR de BurpIA (GitHub API y web fallback fallaron)"
      fi
    fi
    ejecutar "Descargando BurpIA.jar (última versión)" bash -c "
      curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --max-time 120 -o '$burpia_jar' '$burpia_url'"
    if [[ -s "$burpia_jar" ]] && file -b "$burpia_jar" 2>/dev/null | grep -qi 'java\|zip'; then
      _dueno "$burpia_jar"
      info "BurpIA.jar instalado ($(wc -c < "$burpia_jar" | awk '{printf "%.1f MB", $1/1024/1024}'))"
      info "Instalalo desde Burp → Extensions → Add → Extension Type: Java → selecciona ~/Herramientas/BurpIA.jar"
    else
      rm -f "$burpia_jar"
      aviso "BurpIA.jar no es válido (no es JAR): omitido"
    fi
  else
    aviso "BurpIA.jar requiere descarga: corré 'sudo $0 --herramientas'"
  fi
  # jython-standalone: intérprete Python 2.7 sobre JVM (JAR único). Lo usan
  # extensiones Burp Suite en Jython (p. ej. scripts .py en Extensions con
  # Environment Jython). Versión pineada 2.7.4 desde Maven Central (fuente
  # canónica, estable y con checksums publicados).
  local jython_jar="$herramientas/jython-standalone-2.7.4.jar"
  if [[ -s "$jython_jar" ]] && file -b "$jython_jar" 2>/dev/null | grep -qi 'java\|zip'; then
    info "jython-standalone ya está en ~/Herramientas ($(wc -c < "$jython_jar" | awk '{printf "%.1f MB", $1/1024/1024}'))"
  elif (( EUID == 0 )); then
    if _gate_red "descargar jython-standalone" && _gate_disco 64 "jython-standalone (~45MB)"; then
      # Descarga COMO USUARIO al home del usuario (política del script: nada
      # bajo $HOME_REAL se crea como root); validación por firma de JAR.
      ejecutar "Descargando jython-standalone 2.7.4 (Maven Central)" \
        _como_usuario bash -c "curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --max-time 180 -o '$jython_jar.new' 'https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar'"
      if [[ -s "$jython_jar.new" ]] && file -b "$jython_jar.new" 2>/dev/null | grep -qi 'java\|zip'; then
        mv -f "$jython_jar.new" "$jython_jar"
        info "jython-standalone instalado (~45MB): Burp → Extensions → Python Environment → selecciona ~/Herramientas/jython-standalone-2.7.4.jar"
      else
        rm -f "$jython_jar.new"
        aviso "jython-standalone no se descargó o no es un JAR válido: omitido"
      fi
    fi
  else
    aviso "jython-standalone requiere descarga: corré 'sudo $0 --herramientas'"
  fi
  # enumerathor: pipeline de enumeración/validación de subdominios. Instala
  # apt deps (jq/dnsutils/whatweb), Go portable + herramientas (anew/assetfinder/
  # fprobe), uro (pip), binario de findomain según arquitectura y OneForAll.
  # Todas las rutas se derivan del home del usuario, sin hardcodear /root.
  _instalar_enumerathor
  # guake: terminal desplegable (dropdown). En la fase de identidad se crea su
  # launcher en el panel, al lado del de opencode (ver _launcher_guake).
  if command -v guake >/dev/null 2>&1; then
    info "guake ya está instalado ($(guake --version 2>/dev/null | head -1))"
  elif (( EUID == 0 )); then
    ejecutar "Instalando guake (apt)" apt-get install -y -qq --no-install-recommends guake
  else
    aviso "guake no está instalado y requiere root: corré 'sudo $0 --herramientas' (o sudo $0) si lo necesitás."
  fi
  # --- Laboratorio web local: Apache2 + PHP (DOMDocument/SimpleXML/curl) ---
  # Para web-apps del curso que ejercitan SSRF (wrappers HTTP de curl),
  # parsing XML (DOMDocument/SimpleXML) y reglas .htaccess (mod_rewrite).
  # Metapaquetes php-* (no php8.4-*): sobreviven al bump de PHP en Kali
  # rolling. Idempotente: restart SOLO si algo cambió (instalación o a2enmod),
  # nunca en cada corrida.
  _asegurar_apt_pkg apache2 apache2 'apachectl -v 2>&1 | head -1'
  _asegurar_apt_pkg libapache2-mod-php libapache2-mod-php 'dpkg-query -W libapache2-mod-php 2>/dev/null'
  _asegurar_apt_pkg php-xml php-xml 'dpkg-query -W php-xml 2>/dev/null'
  _asegurar_apt_pkg php-curl php-curl 'dpkg-query -W php-curl 2>/dev/null'
  if (( EUID == 0 )) && command -v a2enmod >/dev/null 2>&1; then
    local _web_cambio=0
    if ! apachectl -M 2>/dev/null | grep -q rewrite_module; then
      if ejecutar "Habilitando mod_rewrite (SSRF/.htaccess)" a2enmod rewrite; then
        _web_cambio=1
      fi
    else
      info "mod_rewrite ya está habilitado"
    fi
    if ! systemctl is-active --quiet apache2 2>/dev/null; then
      ejecutar "Arrancando Apache2 (lab web :80)" systemctl start apache2
      _web_cambio=1
    elif (( _web_cambio )); then
      ejecutar "Reiniciando Apache2 (config cambió)" systemctl restart apache2
    else
      info "Apache2 activo sin cambios (no se reinicia)"
    fi
  fi
  # Permisos de ejecución garantizados para todas las herramientas de
  # ~/Herramientas (idempotente: corrige archivos sin +x aunque ya existieran).
  local _perm_ok="" _bin
  for _bin in "$herramientas/wayback_subdomains.sh" \
              "$herramientas/NmapDataExtractor.py" \
              "$herramientas/greenbone.sh" \
              "$herramientas/nmap-parse-output/nmap-parse-output" \
              "$herramientas/nmap-parse-output/_nmap-parse-output" \
              "$herramientas/cupp/cupp.py" \
              "$herramientas/git-dumper/git_dumper.py"; do
    if [[ -f "$_bin" ]] && [[ ! -x "$_bin" ]]; then
      chmod +x "$_bin" 2>/dev/null && _perm_ok="$_perm_ok $(basename "$_bin")"
    fi
  done
  if [[ -n "$_perm_ok" ]]; then
    info "Permisos de ejecución corregidos en:$_perm_ok"
  fi
}

fase_limpieza() {
  titulo_fase "Fase 7/9 · Higiene para distribución"
  # Gate de primera pasada: regenerar llaves SSH y borrar credenciales WiFi
  # rompe known_hosts y configuración de red del operador. Solo la 1ª corrida
  # los hace (mismo patrón que fase_cierre con .distribucion-lista); re-ejecuciones
  # los conservan, así el operador no pierde su setup en cada sudo del script.
  local marker_h="$DIR_ASSETS/.higiene-distro-aplicada"
  if [[ -s "$marker_h" ]]; then
    info "Higiene de distro ya aplicada (1ª pasada): WiFi/SSH se conservan en re-ejecuciones"
  else
    ejecutar "Eliminando credenciales WiFi guardadas" bash -c 'rm -fv /etc/NetworkManager/system-connections/* >/dev/null'
    if ls /etc/ssh/ssh_host_*_key* >/dev/null 2>&1; then
      ejecutar "Regenerando llaves SSH del host" bash -c 'rm -f /etc/ssh/ssh_host_*_key* && dpkg-reconfigure -f noninteractive openssh-server'
    else
      info "Sin servidor SSH: regeneración de llaves omitida"
    fi
    ejecutar "Marcando higiene de distribución aplicada" _escribir "$marker_h" "KALI-DSIO v$VERSION · higiene distro aplicada $(date -u +%FT%TZ)"
  fi
  ejecutar "Compactando logs del sistema" journalctl --vacuum-time=1d
  local objetivos=( ".bash_history" ".viminfo" ".recently-used.xbel" ".mozilla" ".cache/mozilla" ".cache/thumbnails" ".local/share/Trash" )
  local encontrados=()
  local o
  for o in "${objetivos[@]}"; do [[ -e "$HOME_REAL/$o" ]] && encontrados+=("$o"); done
  if (( ${#encontrados[@]} == 0 )); then
    info "El perfil de $USUARIO_REAL ya está limpio"
  else
    local hacer=0
    if (( SIMULAR )); then
      info "En modo real se borraría del perfil de '$USUARIO_REAL': ${encontrados[*]}"
      hacer=1
    else
      aviso "Se borrarán del perfil de '$USUARIO_REAL': ${encontrados[*]}"
      if confirmar; then hacer=1; else info "Limpieza de perfil omitida"; fi
    fi
    if (( hacer )); then
      for o in "${objetivos[@]}"; do
        [[ -e "$HOME_REAL/$o" ]] || continue
        ejecutar "Limpiando ~/$o" rm -rf -- "${HOME_REAL:?}/$o"
      done
      ejecutar "Restaurando historial vacío" bash -c "touch '$HOME_REAL/.bash_history' && chmod 600 '$HOME_REAL/.bash_history' && chown '$USUARIO_REAL':\"\$(id -gn '$USUARIO_REAL')\" '$HOME_REAL/.bash_history'"
    fi
  fi
  ejecutar "Limpiando historiales (bash/zsh) de root y $USUARIO_REAL" _limpiar_historiales
}
 
_escribir_svg() {  # $1 destino · $2 fuente png (por defecto isotipo-blanco)
  # Doble destino: ~/.local/share/icons (debe quedar del USUARIO) y
  # /usr/share/icons (sistema, root). Se decide por ruta, no por llamador.
  local destino="$1" src="${2:-$DIR_TMP_MARCA/isotipo-blanco.png}" b64 contenido
  b64=$(base64 -w0 "$src")
  contenido=$(printf '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="1080" height="1080" viewBox="0 0 1080 1080"><image width="1080" height="1080" xlink:href="data:image/png;base64,%s"/></svg>\n' "$b64")
  if [[ "$destino" == "$HOME_REAL"/* ]]; then
    _como_usuario bash -c "mkdir -p '${destino%/*}'"
    printf '%s\n' "$contenido" > "$destino"
    _dueno "$destino"
  else
    mkdir -p "${destino%/*}"
    printf '%s\n' "$contenido" > "$destino"
  fi
}
 
# Limpia directorios que versiones anteriores del fix creaban por error en
# temas que no los declaran (Flat-Remix usa apps/scalable, no scalable/apps).
# GTK los ignora silenciosamente, pero ensucian el árbol y pueden confundir a
# `find` en iteraciones futuras.
_limpiar_iconos_basura_en() {  # $1 raíz del tema
  local raiz="$1"
  [[ -d "$raiz/scalable/apps" ]] && rm -rf -- "$raiz/scalable/apps"
  [[ -d "$raiz/scalable" ]] || return 0
  rmdir --ignore-fail-on-non-empty "$raiz/scalable" 2>/dev/null || true
}

# Sobrescribe TODAS las copias existentes de los iconos del menú de Kali
# (kali-menu*, kali-panel-menu*) dentro del directorio de un tema de iconos.
# No asume estructura: hicolor usa scalable/apps, pero temas como Flat-Remix
# usan apps/scalable y además duplican el icono en status/scalable/512 — y esa
# copia GANA el best-match de GTK para tamaños 32-64px (es la razón por la que
# el botón del menú seguía mostrando el icono viejo tras sobrescribir apps).
# Rompe symlinks antes de escribir (install seguiría el enlace y corrompería
# el archivo apuntado).
_pisar_iconos_menu_en() {  # $1 raíz del tema (ej. /usr/share/icons/Flat-Remix-Blue-Dark) · $2 svg DragonJAR
  local raiz="$1" svg="$2" f
  [[ -d "$raiz" ]] || return 0
  while IFS= read -r f; do
    [[ -L "$f" ]] && rm -f -- "$f"
    install -m644 "$svg" "$f"
  done < <(find "$raiz" \( -name 'kali-menu.svg' -o -name 'kali-menu-large.svg' \
      -o -name 'kali-panel-menu.svg' -o -name 'kali-panel-menu-large.svg' \) 2>/dev/null)
}

# Instala el icono PROPIO ($ICONO_MENU_PROPIO) en las dos subcarpetas
# estándar de un tema (apps/scalable + status/scalable/512) para garantizar
# el mejor hit independientemente del tamaño que pida GTK.
_instalar_icono_propio_en() {  # $1 raíz del tema · $2 svg DragonJAR
  local raiz="$1" svg="$2"
  [[ -d "$raiz" ]] || return 0
  install -D -m644 "$svg" "$raiz/apps/scalable/${ICONO_MENU_PROPIO}.svg" 2>/dev/null || true
  install -D -m644 "$svg" "$raiz/status/scalable/512/${ICONO_MENU_PROPIO}.svg" 2>/dev/null || true
}

# Id del plugin whiskermenu del panel (o vacío si no existe).
_id_plugin_whisker() {
  local listado prop tipo
  listado=$(_xf_user xfconf-query -c xfce4-panel -l -v 2>/dev/null) || return 1
  while read -r prop tipo; do
    [[ "$prop" == /plugins/plugin-* && "$tipo" == whiskermenu ]] || continue
    printf '%s' "${prop#/plugins/plugin-}"
    return 0
  done <<<"$listado"
  return 1
}

_icono_sistema() {
  # Kali distribuye /usr/share/icons/hicolor/scalable/apps/kali-panel-menu.svg
  # como symlink al tema Flat-Remix: escribir a través del symlink corrompe el
  # tema. Además el botón del menú (whisker) usa el icono "kali-menu", que los
  # temas duplican en varias subcarpetas: sobrescribirlas TODAS (vía find) y
  # fijar un icono propio (dragonjar-menu) como button-icon del whisker.
  local src="$DIR_TMP_MARCA/cabeza.png"
  if [[ ! -s "$src" ]]; then
    src="$DIR_ASSETS/cabeza.png"
  fi
  if [[ ! -s "$src" ]]; then
    aviso "Sin cabeza.png (tmp ni asset persistido): icono del menú no se modifica"
    return 1
  fi
  # 1) Icono canónico DragonJAR en hicolor con nombre propio
  local dest="/usr/share/icons/hicolor/scalable/apps/${ICONO_MENU_PROPIO}.svg"
  mkdir -p "${dest%/*}"
  [[ -L "$dest" ]] && rm -f -- "$dest"
  _escribir_svg "$dest" "$src"
  # 2) hicolor: romper symlinks legacy y sobrescribir kali-menu/kali-panel-menu
  _pisar_iconos_menu_en /usr/share/icons/hicolor "$dest"
  gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
  # 3) Tema ACTIVO del usuario: GTK resuelve primero ahí (puede haber copias en
  #    apps/scalable, status/scalable/512, panel/, etc.)
  local tema
  tema=$(_xf_user xfconf-query -c xsettings -p /Net/IconThemeName 2>/dev/null || true)
  if [[ -n "${tema:-}" && -d "/usr/share/icons/$tema" ]]; then
    _limpiar_iconos_basura_en "/usr/share/icons/$tema"
    _pisar_iconos_menu_en "/usr/share/icons/$tema" "$dest"
    _instalar_icono_propio_en "/usr/share/icons/$tema" "$dest"
    gtk-update-icon-cache -f "/usr/share/icons/$tema" 2>/dev/null || true
  fi
  # 4) Fijar el button-icon del whisker al nombre propio (idempotente)
  local wm
  wm=$(_id_plugin_whisker) || wm=""
  if [[ -n "$wm" ]]; then
    _xf_set xfce4-panel "/plugins/plugin-$wm/button-icon" string "$ICONO_MENU_PROPIO" 2>/dev/null || true
  fi
}

_instalar_enumerathor() {
  # Pipeline de enumeración/validación de subdominios (~/Herramientas/enumerathor.py).
  # Resuelve todas sus dependencias: apt (jq/dnsutils/whatweb), Go portable,
  # herramientas Go (anew/assetfinder/fprobe), uro (pip), binario findomain
  # según arquitectura (amd64/arm64/armhf/i386) y OneForAll.
  # Todas las rutas viven en el home del usuario real; nada hardcodeado a /root.

  local herramientas="$HOME_REAL/Herramientas"
  local enum_py="$herramientas/enumerathor.py"
  # Pastebin como bootstrap si el archivo no existe; el local tiene prioridad
  # (protege los fixes operativos frente a re-descargas).
  local ENUM_PASTEBIN_URL="https://pastebin.com/raw/idYyuLDr"
  if [[ -s "$enum_py" ]] && head -1 "$enum_py" | grep -q '^#!/usr/bin/env python3'; then
    info "enumerathor.py ya está en ~/Herramientas (no se re-descarga)"
  else
    ejecutar "Descargando enumerathor.py desde pastebin" bash -c "
      mkdir -p '$herramientas' &&
      curl -fsSL --max-time 90 -o '$enum_py.new' '$ENUM_PASTEBIN_URL' &&
      sed -i 's/\r\$//' '$enum_py.new' &&
      head -1 '$enum_py.new' | grep -q '^#!/usr/bin/env python3' &&
      python3 -m py_compile '$enum_py.new' &&
      mv '$enum_py.new' '$enum_py' &&
      chmod +x '$enum_py'"
    if [[ ! -s "$enum_py" ]]; then
      aviso "No se pudo descargar enumerathor.py; saltando instalación de deps"
      return 0
    fi
    _dueno "$enum_py"
  fi

  # --- 1. Arquitectura canónica (KDSIO_ARCH de _detectar_sistema) ---
  # Fuente única (DRY): ya no se re-detecta con dpkg||uname en cada bloque.
  local deb_arch go_arch fd_asset
  deb_arch="$KDSIO_ARCH"
  case "$deb_arch" in
    amd64)   go_arch=amd64;  fd_asset=findomain-linux ;;
    arm64)   go_arch=arm64;  fd_asset=findomain-aarch64 ;;
    armhf)   go_arch=armv6l; fd_asset=findomain-armv7 ;;
    i386)    go_arch=386;    fd_asset=findomain-linux-i386 ;;
    *)
      aviso "Arquitectura '$deb_arch' sin soporte enumerathor (amd64/arm64/armhf/i386)"
      return 1 ;;
  esac
  info "enumerathor: arquitectura $deb_arch (go=$go_arch · findomain=$fd_asset)"

  # --- 2. Paquetes apt necesarios (root) ---
  # bin→pkg: el test verifica el BINARIO real, no el nombre del paquete
  # (dnsutils no provee un binario `dnsutils` sino `dig`; ca-certificates no
  # tiene binario y se valida por su store en /etc/ssl).
  local -A apt_bin_pkg=(
    [jq]=jq [dig]=dnsutils [whatweb]=whatweb [unzip]=unzip [curl]=curl
    [git]=git
  )
  local -a faltan=() pkg bin
  for bin in "${!apt_bin_pkg[@]}"; do
    pkg="${apt_bin_pkg[$bin]}"
    command -v "$bin" >/dev/null 2>&1 || faltan+=("$pkg")
  done
  [[ -d /etc/ssl/certs ]] || faltan+=(ca-certificates)
  if [[ ! -x /usr/bin/pip3 ]]; then
    faltan+=(python3-pip)
  fi
  if (( ${#faltan[@]} == 0 )); then
    info "Paquetes apt de enumerathor ya presentes"
  elif (( EUID == 0 )); then
    ejecutar "Instalando paquetes apt enumerathor (${faltan[*]})" \
      apt-get install -y -qq --no-install-recommends "${faltan[@]}"
  else
    aviso "Faltan paquetes apt (${faltan[*]}): requieren root, corré 'sudo $0 --herramientas'"
  fi

  # --- 3. Go portable en ~/Herramientas/go (usuario, sin apt) ---
  # Declaraciones separadas (set -u hace fallar `local a=x b="$a/..."`).
  local go_dir
  local go_bin
  go_dir="$herramientas/go"
  go_bin="$go_dir/bin/go"
  local GO_VER="1.23.4"
  if [[ -x "$go_bin" ]]; then
    info "Go portable ya instalado: $("$go_bin" version 2>/dev/null)"
  elif (( EUID == 0 )); then
    local go_tgz
    go_tgz=$(mktemp "/tmp/kdsio-go-${go_arch}.XXXXXX.tar.gz")
    ejecutar "Descargando Go ${GO_VER} (${go_arch}) en ~/Herramientas/go" bash -c "
      mkdir -p '$go_dir' &&
      curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --max-time 180 -o '$go_tgz' 'https://go.dev/dl/go${GO_VER}.linux-${go_arch}.tar.gz' &&
      tar -C '$go_dir' -xzf '$go_tgz' --strip-components=1; rc=\$?; rm -f '$go_tgz'; exit \$rc"
    if [[ -x "$go_bin" ]]; then
      _dueno "$go_dir"
      info "Go portable instalado: $("$go_bin" version)"
    else
      aviso "Go portable no quedó instalado (¿red caída?): revisá el registro"
    fi
  else
    aviso "Go portable requiere descarga: corré 'sudo $0 --herramientas'"
  fi

  # --- 4. Herramientas Go: anew · assetfinder · fprobe (se compilan como usuario) ---
  # Todas las rutas viven bajo ~/Herramientas/ (GOPATH y GOBIN coherentes con
  # el enumerathor pastebin, que busca ~/Herramientas/gopath/bin).
  # Declaraciones separadas: set -u hace fallar `local a=x b="$a/bin"`.
  local gopath_dir
  local gobin_dir
  gopath_dir="$herramientas/gopath"
  gobin_dir="$gopath_dir/bin"
  if [[ -x "$go_bin" ]]; then
    local -A go_pkgs=(
      [anew]="github.com/tomnomnom/anew@latest"
      [assetfinder]="github.com/tomnomnom/assetfinder@latest"
      [fprobe]="github.com/theblackturtle/fprobe@latest"
      # v2.6.3: última compatible con el Go portable 1.23 (las nuevas >=1.25).
      [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.3"
    )
    local t pkg tbin
    # Iterar las claves del array (DRY: añadir tool al array = entra al loop).
    for t in "${!go_pkgs[@]}"; do
      pkg="${go_pkgs[$t]}"; tbin="$gobin_dir/$t"
      if [[ -x "$tbin" ]]; then
        info "$t ya compilado ($tbin)"
      else
        mkdir -p "$gobin_dir"
        ejecutar "Compilando $t (go install)" \
          _como_usuario env HOME="$HOME_REAL" \
            GOPATH="$gopath_dir" GOBIN="$gobin_dir" \
            PATH="$go_dir/bin:$gobin_dir:$PATH" \
            "$go_bin" install "$pkg"
      fi
    done
    _dueno "$gopath_dir" 2>/dev/null || true
  fi

  # --- 4b. GoLinkFinder (0xsha): extrae endpoints desde archivos JS ---
  # El repo no trae go.mod → se clona, se genera el módulo con deps pineadas
  # (goquery v1.8.1: última compatible con Go 1.23; las nuevas exigen >=1.25)
  # y se compila. Pin por go.mod + go get (go.sum se autogenera con el get).
  if [[ -x "$go_bin" ]]; then
    local glf_bin
    local glf_src
    glf_bin="$gobin_dir/GoLinkFinder"
    glf_src="$herramientas/.src/GoLinkFinder"
    if [[ -x "$glf_bin" ]]; then
      info "GoLinkFinder ya compilado ($glf_bin)"
    else
      mkdir -p "$gobin_dir"
      _git_clonar "$glf_src" "https://github.com/0xsha/GoLinkFinder.git" "GoLinkFinder"
      ejecutar "Compilando GoLinkFinder (deps pineadas + build)" \
        _como_usuario env HOME="$HOME_REAL" GOPATH="$gopath_dir" GOBIN="$gobin_dir" \
          bash -c "
            cd '$glf_src' &&
            '$go_bin' mod init golinkfinder &&
            '$go_bin' mod edit -require=github.com/PuerkitoBio/goquery@v1.8.1 &&
            '$go_bin' mod edit -require=github.com/akamensky/argparse@v1.4.0 &&
            '$go_bin' mod edit -require=github.com/tomnomnom/gahttp@v0.0.0-20180905143706-793a49d82336 &&
            GOPROXY=direct GOSUMDB=off GOTOOLCHAIN=local '$go_bin' get \
              github.com/akamensky/argparse@v1.4.0 \
              github.com/tomnomnom/gahttp@v0.0.0-20180905143706-793a49d82336 \
              github.com/PuerkitoBio/goquery@v1.8.1 &&
            GOPROXY=direct GOSUMDB=off GOTOOLCHAIN=local '$go_bin' build -o '$glf_bin' ."
      if [[ -x "$glf_bin" ]]; then
        _linkear_bin_usuario "$glf_bin" GoLinkFinder
        info "GoLinkFinder compilado + symlink en ~/.local/bin"
      fi
    fi
  fi

  # --- 5. uro (limpiador de URLs duplicadas, pip del usuario) ---
  if [[ -x "$HOME_REAL/.local/bin/uro" ]] \
     || _como_usuario env HOME="$HOME_REAL" \
          PATH="$HOME_REAL/.local/bin:$PATH" bash -c 'command -v uro' >/dev/null 2>&1; then
    info "uro ya disponible"
  else
    ejecutar "Instalando uro (pip3 --user)" \
      _como_usuario env HOME="$HOME_REAL" \
        python3 -m pip install --user --break-system-packages uro || true
  fi

  # --- 6. findomain: binario oficial según arquitectura en ~/Herramientas/findomain/ ---
  # Declaraciones separadas (set -u hace fallar `local a=x b="$a/..."`).
  local fd_dir
  local fd_bin
  fd_dir="$herramientas/findomain"
  fd_bin="$fd_dir/findomain"
  # file -b imprime 'ELF 64-bit LSB ...' (amd64) | 'ELF 64-bit LSB ... ARM aarch64'
  # (arm64) | 'ELF 32-bit LSB ... ARM' (armhf). Tras migrar a KDSIO_ARCH
  # solo hay 4 valores canónicos → case directo (sin sed+dpkg-arch mezclado).
  local fd_pattern
  case "$deb_arch" in
    amd64)   fd_pattern='x86-64' ;;
    arm64)   fd_pattern='ARM aarch64' ;;
    armhf)   fd_pattern='ARM' ;;
    i386)    fd_pattern='Intel 80386' ;;
    *)       fd_pattern='' ;;
  esac
  if [[ -x "$fd_bin" ]] && { [[ -z "$fd_pattern" ]] || file -b "$fd_bin" 2>/dev/null | grep -qF "$fd_pattern"; }; then
    info "findomain ya presente en $fd_bin"
  elif (( EUID == 0 )); then
    ejecutar "Descargando findomain (${fd_asset})" bash -c "
      mkdir -p '$fd_dir' && cd '$fd_dir' &&
      curl -fsSL --max-time 90 -o fd.zip 'https://github.com/Findomain/Findomain/releases/latest/download/${fd_asset}.zip' &&
      unzip -oq fd.zip && chmod +x findomain && rm -f fd.zip"
    if [[ -x "$fd_bin" ]]; then
      _dueno "$fd_dir"
      info "findomain instalado ($("$fd_bin" --version 2>/dev/null | head -1 || echo 'ok'))"
    else
      aviso "findomain no quedó instalado: revisá el registro"
    fi
  else
    aviso "findomain requiere descarga: corré 'sudo $0 --herramientas'"
  fi

  # --- 6b. gospider: spider rápido de URLs/subdominios/archivos/JS ---
  # Pre-compilado por release (mismo patrón que findomain): evita la
  # compilación. El zip extrae a gospider_v*_…/gospider (subcarpeta).
  local GS_VER="1.1.6"
  local gs_dir
  local gs_bin
  gs_dir="$herramientas/gospider"
  gs_bin="$gs_dir/gospider"
  local gs_asset
  # Ya solo nombres canónicos (KDSIO_ARCH): sin aliases x86_64/aarch64/armv7.
  case "$deb_arch" in
    amd64) gs_asset="gospider_v${GS_VER}_linux_x86_64.zip" ;;
    arm64) gs_asset="gospider_v${GS_VER}_linux_arm64.zip" ;;
    armhf) gs_asset="gospider_v${GS_VER}_linux_arm.zip" ;;
    i386)  gs_asset="gospider_v${GS_VER}_linux_i386.zip" ;;
    *)     gs_asset="" ;;
  esac
  if [[ -x "$gs_bin" ]]; then
    info "gospider ya presente en $gs_bin"
  elif [[ -z "$gs_asset" ]]; then
    aviso "gospider sin release para '$deb_arch': omitido"
  elif (( EUID == 0 )); then
    ejecutar "Descargando gospider ($gs_asset)" bash -c "
      mkdir -p '$gs_dir' && cd '$gs_dir' &&
      curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --max-time 120 -o gs.zip \"https://github.com/jaeles-project/gospider/releases/download/v${GS_VER}/${gs_asset}\" &&
      unzip -oq gs.zip && mv -f gospider_v*/gospider . &&
      chmod +x gospider && rm -rf gs.zip gospider_v*"
    if [[ -x "$gs_bin" ]]; then
      _dueno "$gs_dir" 2>/dev/null || true
      _linkear_bin_usuario "$gs_bin" gospider
      info "gospider instalado ($("$gs_bin" --version 2>/dev/null | head -1))"
    else
      aviso "gospider no quedó instalado: revisá el registro"
    fi
  else
    aviso "gospider requiere descarga: corré 'sudo $0 --herramientas'"
  fi

  # --- 7. OneForAll: clonar en ~/Herramientas/OneForAll + deps Python ---
  # Idempotente y robusto: si existe pero está roto (clon parcial sin
  # oneforall.py), se borra y re-clona. Bug previo: git clone rc=128 cuando
  # el directorio existía no vacío. Chequeamos con -s (existe y no vacío),
  # no -x, porque oneforall.py se invoca con `python3 …` y no necesita +x.
  local ofa_dir="$herramientas/OneForAll"
  if [[ -s "$ofa_dir/oneforall.py" ]]; then
    info "OneForAll ya clonado en $ofa_dir"
  else
      _git_clonar "$ofa_dir" "https://github.com/shmilylty/OneForAll.git" "OneForAll (subdomain enumeration)" disposable
  fi
  if [[ -f "$ofa_dir/requirements.txt" ]]; then
    # --user: coherente con la política apt-first (ver _purgar_sombra_pip);
    # sin --user contaminaba el site-packages del sistema.
    ejecutar "Instalando requirements de OneForAll" \
      _como_usuario env HOME="$HOME_REAL" \
        python3 -m pip install --user --break-system-packages -r "$ofa_dir/requirements.txt" || true
    # Python 3.13/3.14 eliminó el módulo 'pipes' que fire 0.4.0 usa: upgrade.
    ejecutar "Actualizando fire (compat. Python 3.14 para OneForAll)" \
      _como_usuario env HOME="$HOME_REAL" \
        python3 -m pip install --user --break-system-packages --upgrade fire || true
  fi

  # --- 8. Symlinks en ~/.local/bin + PATH persistente ---
  _como_usuario bash -c "mkdir -p '$HOME_REAL/.local/bin'"
  # OJO: GOBIN real es $herramientas/gopath/bin (no ~/go/bin); subfinder
  # faltaba en la lista y findomain vive en ~/Herramientas/findomain.
  local -a enlaces=()
  [[ -x "$gobin_dir/anew" ]]       && enlaces+=("$gobin_dir/anew")
  [[ -x "$gobin_dir/assetfinder" ]] && enlaces+=("$gobin_dir/assetfinder")
  [[ -x "$gobin_dir/fprobe" ]]      && enlaces+=("$gobin_dir/fprobe")
  [[ -x "$gobin_dir/subfinder" ]]   && enlaces+=("$gobin_dir/subfinder")
  [[ -x "$fd_bin" ]]                && enlaces+=("$fd_bin")
  [[ -x "$gs_bin" ]]                && enlaces+=("$gs_bin")
  local src lnk
  for src in "${enlaces[@]}"; do
    lnk="$(basename "$src")"
    _linkear_bin_usuario "$src" "$lnk"
  done
  _dueno "$HOME_REAL/.local/bin" "$fd_dir" 2>/dev/null || true

  local bashrc="$HOME_REAL/.bashrc"
  # PATH con layout ~/Herramientas (Go portable + gopath + binarios usuario).
  # Limpieza previa de líneas legacy; el helper crea el archivo si falta y
  # restaura dueño (sed -i como root deja el archivo root-owned si no).
  if [[ -f "$bashrc" ]]; then
    sed -i '/KALI-DSIO: enumerathor/d;/Herramientas\/go\/bin/d;/\$HOME\/go\/bin/d' "$bashrc" 2>/dev/null || true
    _dueno "$bashrc" 2>/dev/null || true
  fi
  _asegurar_path_bashrc "$bashrc" 'Herramientas/gopath/bin' \
    '$HOME/Herramientas/go/bin:$HOME/Herramientas/gopath/bin:$HOME/.local/bin' \
    'enumerathor (Go portable + binarios de usuario)'

  # Smoke test: --help debe responder exit 0 (detecta instalaciones rotas).
  # Sin sudo -u si ya somos el usuario (fallaría pidiendo password).
  local smoke_rc=0
  if (( EUID == 0 )); then
    _como_usuario env HOME="$HOME_REAL" \
      python3 "$enum_py" --help >/dev/null 2>&1 || smoke_rc=$?
  else
    python3 "$enum_py" --help >/dev/null 2>&1 || smoke_rc=$?
  fi
  if (( smoke_rc == 0 )); then
    info "enumerathor verificado (--help exit 0)"
  else
    aviso "enumerathor.py no responde a --help: revisá el registro"
  fi

  info "enumerathor listo. Uso: python3 ~/Herramientas/enumerathor.py -d <dominio> [-v]"
  info "Auto-instalación como fallback: python3 ~/Herramientas/enumerathor.py --instalar-deps"
}

_opt_sonidos() {
  local p
  for p in /Net/EnableEventSounds /Net/EnableInputFeedbackSounds; do
    _xf_set xsettings "$p" bool false
  done
}

_opt_animaciones() {
  # Sin `-H`: _como_usuario ya fija HOME (el flag era un residuo de sudo que
  # recaía sobre `env` y rompía el paso con rc=127).
  _como_usuario bash -c 'mkdir -p ~/.config/gtk-3.0 ~/.config/gtk-4.0 && printf "[Settings]\ngtk-enable-animations=false\n" | tee ~/.config/gtk-3.0/settings.ini ~/.config/gtk-4.0/settings.ini >/dev/null'
}

_opt_pantalla() {
  local p
  for p in /saver/enabled /lock/enabled; do
    _xf_set xfce4-screensaver "$p" bool false
  done
}

_opt_energia() {
  _xf_set xfce4-power-manager /xfce4-power-manager/dpms-enabled bool false
  _xf_set xfce4-power-manager /xfce4-power-manager/inactivity-on-ac int 0
  _xf_set xfce4-power-manager /xfce4-power-manager/blank-mode int 0
}

_opt_fuentes() {
  # Manual de marca: Plus Jakarta Sans titulares · Montserrat UI · IBM Plex Mono técnico
  _xf_set xsettings /Gtk/FontName string "Montserrat 10"
  _xf_set xsettings /Gtk/MonospaceFontName string "IBM Plex Mono 11"
  _xf_set xfwm4 /general/title_font string "Plus Jakarta Sans Bold 10"
}

_opt_memoria() {
  # ponytail: PERCENT=25 sin tope; en hosts con >32 GB RAM conviene SIZE fijo en MB
  _escribir /etc/default/zramswap "ALGO=zstd" "PERCENT=25" "PRIORITY=100"
  # swappiness alto: el swap es zram (RAM comprimida), queremos usarlo antes que el disco
  _escribir /etc/sysctl.d/99-kali-dsio.conf \
    "# KALI-DSIO: zram como swap principal" "vm.swappiness=180" "vm.vfs_cache_pressure=50"
  sysctl -p /etc/sysctl.d/99-kali-dsio.conf >/dev/null
  systemctl restart zramswap >>"$REGISTRO" 2>&1
}

fase_xfce() {
  titulo_fase "Fase 8/9 · Optimización XFCE y sistema"
  if [[ $SIMULAR -eq 1 ]]; then
    paso_simulado "Compositor de xfwm4 desactivado"
    paso_simulado "Sonidos de eventos desactivados"
    paso_simulado "Animaciones GTK3/GTK4 desactivadas"
    paso_simulado "Salvapantallas y bloqueo desactivados"
    paso_simulado "DPMS y auto-apagado desactivados"
    paso_simulado "zram instalado (swap comprimido en RAM)"
    paso_simulado "Sysctl ajustado (swappiness=180 para zram)"
    return 0
  fi
  if (( ! SESION_GRAFICA )); then
    info "Sin sesión gráfica activa: se omiten los ajustes de escritorio"
  else
    local comp
    comp=$(_xf_user xfconf-query -c xfwm4 -p /general/use_compositing 2>/dev/null || echo activo)
    if [[ "$comp" == "false" ]]; then
      PASO_ACTUAL=$((PASO_ACTUAL + 1)); TOTAL_PASOS=$((TOTAL_PASOS + 1)); barra
      printf '  Compositor xfwm4  %s✓ ya estaba desactivado%s\n' "$VERDE$B" "$R"
      PASOS_OK=$((PASOS_OK + 1))
    else
      ejecutar "Desactivando compositor de xfwm4" _xf_set xfwm4 /general/use_compositing bool false
    fi
    ejecutar "Desactivando sonidos de eventos" _opt_sonidos
    ejecutar "Desactivando animaciones GTK3/GTK4" _opt_animaciones
    ejecutar "Desactivando salvapantallas y bloqueo" _opt_pantalla
    ejecutar "Desactivando DPMS y auto-apagado de pantalla" _opt_energia
  fi
  printf '\n'
  ejecutar "Instalando zram-tools (swap comprimido en RAM)" \
    apt-get install -y -qq --no-install-recommends zram-tools
  ejecutar "Configurando zram y sysctl (swappiness=180)" _opt_memoria
}
 
_avatar_usuario() {
  # Manual de marca: avatar oficial exportado; nunca se regenera a mano
  local src="$DIR_TMP_MARCA/avatar-oficial.png"
  _instalado "$src" || src="$DIR_TMP_MARCA/isotipo-blanco.png"
  mkdir -p /var/lib/AccountsService/icons /var/lib/AccountsService/users
  install -m644 "$src" "/var/lib/AccountsService/icons/$USUARIO_REAL"
  local uf="/var/lib/AccountsService/users/$USUARIO_REAL"
  if [[ -f "$uf" ]] && grep -q '^Icon=' "$uf"; then
    sed -i "s|^Icon=.*|Icon=/var/lib/AccountsService/icons/$USUARIO_REAL|" "$uf"
  elif [[ -f "$uf" ]]; then
    printf 'Icon=/var/lib/AccountsService/icons/%s\n' "$USUARIO_REAL" >> "$uf"
  else
    printf '[User]\nIcon=/var/lib/AccountsService/icons/%s\n' "$USUARIO_REAL" > "$uf"
  fi
  chmod 644 "/var/lib/AccountsService/icons/$USUARIO_REAL" "$uf"
}

_terminal_marca() {  # $1 destino del terminalrc — misma definición para usuario y /etc/skel
  local mono="IBM Plex Mono" nf
  # Nerd Fonts usa hoy la familia "BlexMono Nerd Font Mono" (antes IBMPlexMono):
  # detectamos cualquiera de las dos y la aplicamos si está instalada.
  nf=$(fc-list 2>/dev/null | grep -oiE '(BlexMono|IBMPlexMono) Nerd Font Mono' | head -1)
  [[ -n "$nf" ]] || nf=$(fc-list 2>/dev/null | grep -oiE '(BlexMono|IBMPlexMono) Nerd Font' | head -1)
  [[ -n "$nf" ]] && mono="$nf"
  # Paleta del manual: negro/rojo marca/blanco roto + severidades CVSS
  # (crítico 890F0A queda como fondo; alto FF0000, medio FBB03B, bajo 40A9F6,
  #  informativa 46586B). Verde/magenta/cian se conservan funcionales para
  # ls/vim/git — el manual no los define.
  _escribir_usuario "$1" \
    "FontName=$mono 11" \
    'ColorForeground=#faf8f6' \
    'ColorBackground=#0a0a0a' \
    'ColorCursor=#c11b05' \
    'ColorPalette=#0a0a0a;#c11b05;#5faf5f;#fbb03b;#40a9f6;#af5faf;#5fafaf;#faf8f6;#46586b;#ff0000;#87d787;#ffd787;#87afff;#ff87ff;#87d7ff;#ffffff' \
    'ScrollingBar=TERMINAL_SCROLLBAR_RIGHT'
}

_escribir_xcompose() {  # $1 destino — símbolos frecuentes para reportes
  _escribir_usuario "$1" \
    'include "%L"' \
    '<Multi_key> <minus> <greater>    : "→"   U2192' \
    '<Multi_key> <v> <equal>          : "✓"   U2713' \
    '<Multi_key> <x> <equal>          : "✗"   U2717' \
    '<Multi_key> <x> <x>              : "×"   U00D7' \
    '<Multi_key> <plus> <minus>       : "±"   U00B1' \
    '<Multi_key> <t> <m>              : "™"   U2122' \
    '<Multi_key> <greater> <equal>    : "≥"   U2265' \
    '<Multi_key> <exclam> <equal>     : "≠"   U2260' \
    '<Multi_key> <e> <equal>          : "€"   U20AC'
}

_skel_marca() {  # nuevos usuarios nacen con terminal y XCompose de marca
  _terminal_marca /etc/skel/.config/xfce4/terminal/terminalrc
  _escribir_xcompose /etc/skel/.XCompose
}

_icono_opencode() {
  # Descarga el icono oficial de opencode al home del usuario real (idempotente).
  local icono="$HOME_REAL/$ICONO_OPENCODE_REL"
  if [[ -s "$icono" ]] && file -b "$icono" 2>/dev/null | grep -qi "png"; then
    info "Icono de opencode ya presente ($icono)"
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    aviso "curl no disponible: no se pudo descargar el icono de opencode"
    return 1
  fi
  ejecutar "Descargando icono oficial de opencode" \
    _como_usuario bash -c "mkdir -p '${icono%/*}' && curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --max-time 60 -o '$icono' '$ICONO_OPENCODE_URL'"
  if [[ -s "$icono" ]] && file -b "$icono" 2>/dev/null | grep -qi "png"; then
    _dueno "$icono"
    info "Icono de opencode instalado"
    return 0
  fi
  aviso "El icono de opencode no se descargó correctamente"
  return 1
}

# Nombres de .desktop que identifican a los launchers del panel.
OPENCODE_DESKTOP="opencode.desktop"
GUAKE_DESKTOP="guake.desktop"

# Añade un launcher (`.desktop`) al panel Xfce con un Exec/Icono dados e idempotente:
# si el `.desktop` ya está en el panel no lo duplica. El nuevo plugin se inserta
# justo después del plugin launcher cuyo `_items` contenga a `_ancla` (útil para
# "poner X al lado de Y"); si `_ancla` está vacío o no existe, se inserta después
# del último plugin de tipo launcher (≈ la terminal). Argumentos:
#   $1 _nombre    : etiqueta mostrada (para logs y Name del .desktop)
#   $2 _desktop   : nombre del archivo .desktop (identificador único)
#   $3 _exec      : comando del Exec
#   $4 _icono     : ruta o nombre de icono
#   $5 _terminal  : "true"/"false" para Terminal=
#   $6 _ancla     : .desktop que actúa como punto de inserción ("" = tras terminal)
# Crea un enlace web Type=Link como .desktop (ej. los de ~/Herramientas).
# Idempotente: si el .desktop ya existe, no lo sobrescribe (principio de menor
# sorpresa; los cambios los hace el usuario editando el archivo).
# $1 ruta destino SIN extensión · $2 nombre visible · $3 URL · $4 icono
_enlace_web() {
  local destino="$1" nombre="$2" url="$3" icono="${4:-web-browser}"
  if [[ -e "${destino}.desktop" ]]; then
    info "$(basename "$destino").desktop ya está en ${destino%/*}"
    return 0
  fi
  ejecutar "Creando enlace $(basename "$destino") en ${destino%/*}" \
    _como_usuario bash -c "mkdir -p '${destino%/*}' && printf '%s\n' \
      '#!/usr/bin/env xdg-open' \
      '[Desktop Entry]' \
      'Version=1.0' \
      'Type=Link' \
      'Name=$nombre' \
      'URL=$url' \
      'Icon=$icono' \
      > '${destino}.desktop' && chmod +x '${destino}.desktop'"
}

_launcher_panel() {
  (( ! SESION_GRAFICA )) && return 0
  local _nombre="$1" _desktop="$2" _exec="$3" _icono="$4" _terminal="$5" _ancla="${6:-}"

  # 1) Un listado único de propiedades sirve para la idempotencia (aquí) y para
  #    el posicionamiento (paso 7): evita una lectura xfconf por cada plugin.
  local listado
  listado=$(_xf_user xfconf-query -c xfce4-panel -l -v 2>/dev/null) || {
    aviso "No se pudo leer la configuración del panel (¿sesión gráfica activa?)"
    return 1
  }
  if grep -qF -- "$_desktop" <<<"$listado"; then
    info "Launcher de $_nombre ya está en el panel (se omite)"
    return 0
  fi

  # 2) Leer los ids actuales de plugins (solo líneas que son enteros).
  local antes nuevo_id
  antes=$(_xf_user xfconf-query -c xfce4-panel -p /panels/panel-1/plugin-ids 2>/dev/null \
           | awk '/^[0-9]+$/{printf "%s ", $1}')
  antes="${antes% }"

  # 3) Crear un plugin launcher de forma nativa (el panel asigna el id siguiente).
  _xf_user xfce4-panel --add=launcher >/dev/null 2>&1 \
    || { aviso "No se pudo añadir el launcher de $_nombre"; return 1; }

  # 4) Detectar el id nuevo (el que no estaba antes).
  local despues d
  despues=$(_xf_user xfconf-query -c xfce4-panel -p /panels/panel-1/plugin-ids 2>/dev/null \
            | awk '/^[0-9]+$/{printf "%s ", $1}')
  despues="${despues% }"
  nuevo_id=""
  for d in $despues; do
    case " $antes " in
      *" $d "*) ;;
      *) nuevo_id="$d"; break ;;
    esac
  done
  if [[ -z "$nuevo_id" ]]; then
    aviso "No se detectó el plugin launcher creado para $_nombre"
    return 1
  fi

  # 5) Configurar el items del nuevo launcher como array con el .desktop
  #    (--force-array: un único elemento sigue siendo array).
  _xf_user xfconf-query -c xfce4-panel -p "/plugins/plugin-$nuevo_id/items" \
      -a -n -t string -s "$_desktop" >/dev/null 2>&1 \
    || { aviso "No se pudo configurar el launcher de $_nombre"; return 1; }

  # 6) Dejar el .desktop en launcher-<id>/ y corregir dueño del directorio
  #    completo (cubre dir+archivo, sea root o el usuario quien escriba).
  local ldir="$HOME_REAL/$PANEL_DIR_REL/launcher-$nuevo_id"
  _escribir "$ldir/$_desktop" \
    '[Desktop Entry]' 'Version=1.0' 'Type=Application' \
    "Name=$_nombre" \
    "Exec=$_exec" \
    "Icon=$_icono" \
    "Terminal=$_terminal" 'StartupNotify=true' 'Categories=Development;Utility;'
  _dueno "$ldir"

  # 7) Posicionar el id nuevo: tras el plugin cuyo items contenga el ancla (ej.
  #    opencode) o, si no hay ancla/encontrada, tras el último launcher. El
  #    listado fresco se parsea UNA vez en arrays asociativos (eficiente).
  local -a ids=() resultado=()
  local v; for v in $despues; do [[ "$v" != "$nuevo_id" ]] && ids+=("$v"); done
  declare -A tipo=() items=()
  local prop val idp
  listado=$(_xf_user xfconf-query -c xfce4-panel -l -v 2>/dev/null)
  while read -r prop val; do
    [[ "$prop" == /plugins/plugin-* ]] || continue
    idp="${prop#/plugins/plugin-}"
    if [[ "$prop" == */items ]]; then
      items["${idp%/items}"]="$val"
    else
      tipo["$idp"]="$val"
    fi
  done <<<"$listado"
  local i pos=-1
  if [[ -n "$_ancla" ]]; then
    for i in "${!ids[@]}"; do
      if [[ "${items[${ids[$i]}]:-}" == *"$_ancla"* ]]; then pos=$i; break; fi
    done
  fi
  if (( pos < 0 )); then
    for i in "${!ids[@]}"; do
      [[ "${tipo[${ids[$i]}]:-}" == "launcher" ]] && pos=$i
    done
  fi
  for i in "${!ids[@]}"; do
    resultado+=("${ids[$i]}")
    if [[ $i == "$pos" ]]; then
      resultado+=("$nuevo_id")
    fi
  done
  if [[ " ${resultado[*]} " != *" $nuevo_id "* ]]; then
    resultado+=("$nuevo_id")
  fi
  local -a args=(); for v in "${resultado[@]}"; do args+=(-t int -s "$v"); done
  _xf_user xfconf-query -c xfce4-panel -p /panels/panel-1/plugin-ids "${args[@]}" >/dev/null 2>&1

  info "Launcher de $_nombre añadido al panel"
}

_launcher_opencode() {
  # Launcher de opencode en el panel, detrás de la terminal.
  local oc="$HOME_REAL/.opencode/bin/opencode"
  [[ -x "$oc" ]] || { info "opencode no instalado: launcher del panel omitido"; return 0; }
  _icono_opencode || return 0
  _launcher_panel "opencode" "$OPENCODE_DESKTOP" "$oc" \
    "$HOME_REAL/$ICONO_OPENCODE_REL" "true" ""
}

_launcher_guake() {
  # Launcher de guake en el panel, justo al lado de opencode (ancla = opencode).
  command -v guake >/dev/null 2>&1 \
    || { info "guake no instalado: launcher del panel omitido"; return 0; }
  _launcher_panel "guake" "$GUAKE_DESKTOP" "guake" "guake" "false" "$OPENCODE_DESKTOP"
}

_marca_usuario() {
  # Todo este bloque opera sobre ~/.local/share/icons (y ~/.config del
  # usuario): se ejecuta COMO USUARIO vía _como_usuario para que los
  # archivos/atoms queden kali:kali desde el origen, no root+chown (si la
  # corrida abortara antes del _dueno, la identidad quedaría root-owned).
  local u="$HOME_REAL/.local/share/icons"
  local cabeza="$DIR_TMP_MARCA/cabeza.png"
  [[ -s "$cabeza" ]] || cabeza="$DIR_TMP_MARCA/isotipo-blanco.png"
  # Icono PROPIO de marca (sobrevive a cambios de tema y actualizaciones de
  # kali-themes-common, que es lo que redistribuye kali-menu/kali-panel-menu).
  _como_usuario bash -c "mkdir -p '$u/hicolor/256x256/apps' && install -m644 '$cabeza' '$u/hicolor/256x256/apps/${ICONO_MENU_PROPIO}.png'"
  if command -v convert >/dev/null 2>&1; then
    _como_usuario bash -c "mkdir -p '$u/hicolor/48x48/apps' && convert '$cabeza' -resize 48x48 PNG32:'$u/hicolor/48x48/apps/${ICONO_MENU_PROPIO}.png'"
  fi
  _como_usuario bash -c "mkdir -p '$u/hicolor/scalable/apps'"
  _escribir_svg "$u/hicolor/scalable/apps/${ICONO_MENU_PROPIO}.svg" "$cabeza"
  # Compatibilidad: pisar también los kali-menu/kali-panel-menu que el tema
  # activo expone (especialmente status/scalable/512/kali-menu.svg en
  # Flat-Remix, que gana el best-match de GTK para tamaños 32-64px y era la
  # causa raíz de que el icono del menú no cambiara).
  _escribir_svg "$u/hicolor/scalable/apps/kali-menu.svg"       "$cabeza"
  _escribir_svg "$u/hicolor/scalable/apps/kali-panel-menu.svg" "$cabeza"
  gtk-update-icon-cache -f -t "$u/hicolor" 2>/dev/null || true
  local tema mon
  tema=$(_xf_user xfconf-query -c xsettings -p /Net/IconThemeName 2>/dev/null || true)
  if [[ -n "${tema:-}" && -d "$u/$tema" ]]; then
    # Sobrescribir TODAS las copias del tema activo (apps/scalable,
    # status/scalable/512, panel/, etc.) sin asumir estructura.
    _limpiar_iconos_basura_en "$u/$tema"
    _pisar_iconos_menu_en "$u/$tema" \
      "$u/hicolor/scalable/apps/${ICONO_MENU_PROPIO}.svg"
    # Instalar el icono propio en las rutas estándar del tema activo
    # (mejor hit que hicolor cuando el tema define el tamaño exacto).
    _instalar_icono_propio_en "$u/$tema" \
      "$u/hicolor/scalable/apps/${ICONO_MENU_PROPIO}.svg"
    gtk-update-icon-cache -f -t "$u/$tema" 2>/dev/null || true
  fi
  # Los helpers de tema (pisar/limpiar/instalar) aún corren como root porque
  # también atienden /usr/share/icons; este chown deja el árbol del usuario
  # kali:kali pase lo que pase.
  _dueno "$u"
  mon=$(_xf_user xrandr 2>/dev/null | awk '/ connected/{print $1; exit}')
  if [[ -n "${mon:-}" ]]; then
    _xf_set xfce4-desktop "/backdrop/screen0/monitor$mon/workspace0/image-style" int 5
    _xf_set xfce4-desktop "/backdrop/screen0/monitor$mon/workspace0/last-image" string \
      "/usr/share/images/desktop-base/dragonjar-wallpaper.png"
  fi
  _terminal_marca "$HOME_REAL/.config/xfce4/terminal/terminalrc"
  _escribir_xcompose "$HOME_REAL/.XCompose"
  _panel_marca
  # Crear los launchers ANTES de reiniciar el panel: así al relanzarlo, ya
  # están en plugin-ids y aparecen en el orden correcto desde el primer paint.
  _launcher_opencode || true
  _launcher_guake || true
  _arrancar_panel_usuario
  # Fijar button-icon del whisker al nombre propio (idempotente).
  local wm
  wm=$(_id_plugin_whisker) || wm=""
  if [[ -n "$wm" ]]; then
    _xf_set xfce4-panel "/plugins/plugin-$wm/button-icon" string "$ICONO_MENU_PROPIO" 2>/dev/null || true
  fi
}

_panel_marca() {
  # ponytail: solo props xfconf seguras; el XML de plugins del panel no se toca (frágil entre versiones)
  _xf_set xfce4-panel /panels/dark-mode bool true
  _xf_set xfce4-panel /panels/panel-1/position string "p=6;x=0;y=0"
  _xf_set xfce4-panel /panels/panel-1/size int 46
  _xf_set xfce4-panel /panels/panel-1/length int 100
}

_programar_marca_autostart() {
  # Se ejecuta una sola vez en el primer login gráfico y se autodestruye
  local d="$HOME_REAL/.config/autostart/kali-dsio-marca.desktop"
  _escribir "$d" \
    '[Desktop Entry]' 'Type=Application' \
    'Name=KALI-DSIO · Identidad DragonJAR' \
    "Exec=sh -c \"rm -f '$d'; /usr/local/bin/kali-dsio --marca-usuario\"" \
    'Terminal=false'
  _dueno "$d"
}

_opt_consola() {
  _escribir /etc/motd "$_ARTE_DRAGONJAR" "" "  Preparada por DragonJAR · KALI-DSIO v${VERSION}"
  # \s \r \l los expande agetty al mostrar el prompt de login
  _escribir /etc/issue "$_ARTE_DRAGONJAR" "" "  Kali GNU/Linux \\s (\\r) · tty \\l" ""
}
 
_verificar_dependencias() {
  local falta=()
  command -v curl >/dev/null   || falta+=(curl)
  command -v convert >/dev/null || falta+=(imagemagick)
  command -v unzip >/dev/null  || falta+=(unzip)
  ((${#falta[@]} == 0)) && return 0
  info "Instalando dependencias faltantes: ${falta[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${falta[@]}" >>"$REGISTRO" 2>&1
}

_webapps_marca() {  # plataformas del curso como aplicaciones del menú (sin favicons: icono del sistema)
  local -A apps=(
    [dragonjar]="https://www.dragonjar.org"
    [hackerone]="https://hackerone.com"
    [bugcrowd]="https://bugcrowd.com"
    [shodan]="https://www.shodan.io"
    [censys]="https://search.censys.io"
    [virustotal]="https://www.virustotal.com"
  )
  local n
  for n in "${!apps[@]}"; do
    _escribir "/usr/share/applications/dsio-$n.desktop" \
      '[Desktop Entry]' 'Type=Application' \
      "Name=${n^}" "Exec=xdg-open ${apps[$n]}" \
      'Icon=web-browser' 'Categories=Network;Security;'
  done
}
 
fase_marca() {
  titulo_fase "Fase 9/9 · Identidad DragonJAR (manual de marca)"
  if [[ $SIMULAR -eq 1 ]]; then
    paso_simulado "Descargar isotipo, avatar y tipografías oficiales"
    paso_simulado "Instalar tipografías de marca + IBM Plex Mono Nerd"
    paso_simulado "Fondo GRUB de marca + wallpaper oficial Desktop.jpg (escritorio/LightDM)"
    paso_simulado "Avatar oficial del usuario"
    paso_simulado "Web-apps de seguridad en el menú"
    paso_simulado "Tipografías del manual aplicadas a la sesión"
    paso_simulado "Terminal (paleta severidades CVSS), panel y escritorio"
    paso_simulado "Branding de consola (issue/motd)"
    paso_simulado "Esqueleto heredable (/etc/skel)"
    return 0
  fi
  rm -rf "$DIR_TMP_MARCA"; mkdir -p "$DIR_TMP_MARCA"
  ejecutar "Verificando herramientas requeridas" _verificar_dependencias
  ejecutar "Instalando comando kali-dsio (/usr/local/bin)" bash -c 'install -m755 "$1" /usr/local/bin/kali-dsio && ln -sf /usr/local/bin/kali-dsio /usr/local/sbin/kali-dsio' _ "$0"
  ejecutar "Descargando isotipo oficial blanco" bash -c "curl -fsSL --max-time 60 -o '$DIR_TMP_MARCA/isotipo-blanco.png' '$BASE_MARCA/isotipo-blanco.png' || true"
  if [[ ! -s "$DIR_TMP_MARCA/isotipo-blanco.png" ]] && _instalado "$DIR_ASSETS/isotipo-blanco.png"; then
    info "Sin conexión: se usa el isotipo persistido en $DIR_ASSETS"
    cp "$DIR_ASSETS/isotipo-blanco.png" "$DIR_TMP_MARCA/isotipo-blanco.png"
  elif [[ ! -s "$DIR_TMP_MARCA/isotipo-blanco.png" ]]; then
    info "Sin conexión ni isotipo persistido: se conserva la identidad ya instalada"
    return 0
  else
    ejecutar "Persistiendo isotipo en $DIR_ASSETS" install -Dm644 "$DIR_TMP_MARCA/isotipo-blanco.png" "$DIR_ASSETS/isotipo-blanco.png"
  fi
  # Icono del menú de inicio: cabeza oficial del repositorio (preserva transparencia).
  ejecutar "Descargando icono del menú (cabeza.png)" bash -c "curl -fsSL --max-time 60 -o '$DIR_TMP_MARCA/cabeza.png' 'https://raw.githubusercontent.com/DragonJAR/KALI-DSIO/main/cabeza.png' || true"
  if [[ ! -s "$DIR_TMP_MARCA/cabeza.png" ]] && _instalado "$DIR_ASSETS/cabeza.png"; then
    info "Sin conexión: se usa el icono persistido en $DIR_ASSETS"
    cp "$DIR_ASSETS/cabeza.png" "$DIR_TMP_MARCA/cabeza.png"
  elif [[ -s "$DIR_TMP_MARCA/cabeza.png" ]]; then
    ejecutar "Persistiendo icono del menú en $DIR_ASSETS" install -Dm644 "$DIR_TMP_MARCA/cabeza.png" "$DIR_ASSETS/cabeza.png"
  fi
  if _fuentes_instaladas; then
    info "Tipografías de marca ya instaladas: descarga omitida"
  else
    ejecutar "Descargando tipografías de marca" bash -c "curl -fsSL --max-time 90 -o '$DIR_TMP_MARCA/jakarta.ttf' 'https://github.com/google/fonts/raw/main/ofl/plusjakartasans/PlusJakartaSans%5Bwght%5D.ttf'; curl -fsSL --max-time 90 -o '$DIR_TMP_MARCA/montserrat.ttf' 'https://github.com/google/fonts/raw/main/ofl/montserrat/Montserrat%5Bwght%5D.ttf'; curl -fsSL --max-time 90 -o '$DIR_TMP_MARCA/plexmono.ttf' 'https://github.com/google/fonts/raw/main/ofl/ibmplexmono/IBMPlexMono-Regular.ttf'; true"
    if [[ ! -s "$DIR_TMP_MARCA/jakarta.ttf" ]]; then
      aviso "Tipografías no descargadas: se aplican solo icono y fondos"
    else
      ejecutar "Instalando tipografías de marca" bash -c "mkdir -p '$DIR_FUENTES' && install -m644 '$DIR_TMP_MARCA/jakarta.ttf' '$DIR_FUENTES/PlusJakartaSans.ttf' && install -m644 '$DIR_TMP_MARCA/montserrat.ttf' '$DIR_FUENTES/Montserrat.ttf' && install -m644 '$DIR_TMP_MARCA/plexmono.ttf' '$DIR_FUENTES/IBMPlexMono-Regular.ttf' && fc-cache -f >/dev/null 2>&1"
    fi
  fi
  if _plex_nerd_instalada; then
    info "IBM Plex Mono Nerd ya instalada: descarga omitida"
  else
    ejecutar "Descargando IBM Plex Mono Nerd (glifos para terminal)" bash -c "curl -fsSL --max-time 90 -o '$DIR_TMP_MARCA/plexnerd.zip' 'https://github.com/ryanoasis/nerd-fonts/releases/latest/download/IBMPlexMono.zip' || true"
    if _instalado "$DIR_TMP_MARCA/plexnerd.zip"; then
      ejecutar "Instalando IBM Plex Mono Nerd" _instalar_plex_nerd
    else
      aviso "Nerd Font no descargada: el terminal usará IBM Plex Mono estándar"
    fi
  fi
  ejecutar "Descargando avatar oficial de redes" bash -c "curl -fsSL --max-time 60 -o '$DIR_TMP_MARCA/avatar-oficial.png' '$BASE_MARCA/avatar-1024x1024-1.png' || true"
  # GRUB conserva el fondo de marca generado (#000000 + isotipo); el escritorio
  # (y LightDM, vía dragonjar-wallpaper.png) usa el fondo oficial Desktop.jpg
  # del repo. Fallbacks: asset persistido → fondo de marca generado.
  ejecutar "Generando fondo de marca para GRUB (#000000)" convert -size 1920x1080 xc:'#000000' \( "$DIR_TMP_MARCA/isotipo-blanco.png" -resize 300x300 \) -gravity center -composite PNG24:"$DIR_TMP_MARCA/fondo.png"
  local wp_src="$DIR_TMP_MARCA/fondo.png"
  ejecutar "Descargando fondo de escritorio oficial (Desktop.jpg)" bash -c "curl -fsSL --max-time 90 -o '$DIR_TMP_MARCA/Desktop.jpg' 'https://raw.githubusercontent.com/DragonJAR/KALI-DSIO/main/Desktop.jpg' || true"
  if [[ -s "$DIR_TMP_MARCA/Desktop.jpg" ]] && file -b "$DIR_TMP_MARCA/Desktop.jpg" | grep -qi JPEG; then
    ejecutar "Persistiendo fondo de escritorio en $DIR_ASSETS" install -Dm644 "$DIR_TMP_MARCA/Desktop.jpg" "$DIR_ASSETS/Desktop.jpg"
    ejecutar "Convirtiendo Desktop.jpg a PNG de escritorio" convert "$DIR_TMP_MARCA/Desktop.jpg" PNG24:"$DIR_TMP_MARCA/wallpaper.png"
    wp_src="$DIR_TMP_MARCA/wallpaper.png"
  elif _instalado "$DIR_ASSETS/Desktop.jpg"; then
    info "Sin conexión: se usa el fondo de escritorio persistido en $DIR_ASSETS"
    ejecutar "Convirtiendo fondo persistido a PNG" convert "$DIR_ASSETS/Desktop.jpg" PNG24:"$DIR_TMP_MARCA/wallpaper.png"
    wp_src="$DIR_TMP_MARCA/wallpaper.png"
  else
    aviso "Desktop.jpg no disponible: el escritorio usará el fondo de marca generado"
  fi
  ejecutar "Instalando icono del menú (kali-panel-menu)" _icono_sistema
  ejecutar "Aplicando fondo a GRUB y escritorio" bash -c "install -m644 '$DIR_TMP_MARCA/fondo.png' /usr/share/images/desktop-base/desktop-grub.png && install -m644 '$wp_src' /usr/share/images/desktop-base/dragonjar-wallpaper.png"
  ejecutar "Fondo GRUB persistente (grub.d)" _escribir /etc/default/grub.d/99-kali-dsio.cfg \
    "GRUB_BACKGROUND=/usr/share/images/desktop-base/desktop-grub.png"
  ejecutar "Branding de consola (/etc/issue, /etc/motd)" _opt_consola
  if [[ -d /etc/lightdm ]]; then
    ejecutar "Configurando pantalla de login (LightDM)" bash -c "CONF=/etc/lightdm/lightdm-gtk-greeter.conf; touch \$CONF; cp -n \$CONF \$CONF.bak-kdsio 2>/dev/null || true; sed -i '/^background=/d;/^font-name=/d' \$CONF; grep -q '^\[greeter\]' \$CONF || printf '%s\n' '[greeter]' >> \$CONF;       printf '%s\n' 'background=/usr/share/images/desktop-base/dragonjar-wallpaper.png' 'font-name=Montserrat 10' >> \$CONF"
  else
    info "LightDM no presente: pantalla de login se omite"
  fi
  if command -v update-grub >/dev/null 2>&1; then
    ejecutar "Regenerando menú GRUB" update-grub
  else
    info "GRUB no presente: regeneración omitida"
  fi
  ejecutar "Web-apps de seguridad en el menú" _webapps_marca
  ejecutar "Definiendo avatar del usuario (oficial de marca)" _avatar_usuario
  if (( SESION_GRAFICA )); then
    ejecutar "Aplicando tipografías del manual a la sesión" _opt_fuentes
    ejecutar "Aplicando panel dock, escritorio, iconos y terminal" _marca_usuario
  else
    info "Sin sesión gráfica: la marca se aplicará sola en el primer inicio de sesión"
    ejecutar "Programando marca al primer login (autostart)" _programar_marca_autostart
  fi
  ejecutar "Esqueleto heredable para nuevos usuarios (/etc/skel)" _skel_marca
}

fase_cierre() {
  # Higiene tipo virt-sysprep SOLO en la primera construcción de la imagen.
  # Vaciar las listas de apt y regenerar el machine-id en re-ejecuciones
  # rompería un sistema ya en uso (DBus/sesión activas), por eso se marca
  # la primera pasada y en las siguientes se omite.
  local marker="$DIR_ASSETS/.distribucion-lista"
  if [[ -s "$marker" ]] || [[ -f /etc/machine-id && ! -s /etc/machine-id ]]; then
    info "Higiene de distribución ya aplicada: se omite en esta pasada"
    return 0
  fi
  ejecutar "Vaciando listas de apt (se repone con apt update)" rm -rf /var/lib/apt/lists/*
  # Cada clon debe nacer con un machine-id vacío para que systemd genere uno
  # único en el primer arranque (patrón virt-sysprep).
  ejecutar "Regenerando machine-id de la máquina" bash -c 'truncate -s0 /etc/machine-id && rm -f /var/lib/dbus/machine-id'
  ejecutar "Marcando distribución lista (primera pasada)" _escribir "$marker" "KALI-DSIO listo · primera pasada"
}

modo_herramientas() {
  # Modo solo-herramientas: instala pipx, bbot, las dependencias y el contenido
  # de ~/Herramientas (eValidator.py y Cateyes.jpg). No toca el resto del sistema.
  titulo_fase "Solo herramientas · pipx, bbot y ~/Herramientas"
  if [[ $SIMULAR -eq 1 ]]; then
    # Guard SIMULAR: sin esto, `--herramientas --simular` ejecutaba de VERDAD
    # git fetch+reset --hard, sed -i del bashrc, pipx ensurepath y mkdir/symlink
    # (fase_pentest sí lo tiene; este modo converge en instalar_herramientas).
    paso_simulado "pipx + bbot + dependencias Python"
    paso_simulado "${HOME_REAL}/Herramientas (eValidator.py, Cateyes.jpg, wayback_subdomains.sh, NmapDataExtractor.py, prueba.xml, acccheck.py, badpdf.py)"
    paso_simulado "Clones git (nmap-parse-output, cupp, ghauri, commix, sippts, x8, nuclei-templates, OneForAll)"
    paso_simulado "Herramientas Go portables (anew, assetfinder, fprobe, subfinder, GoLinkFinder, findomain, gospider)"
    paso_simulado "Burp Suite + config BurpIA + parche embedded browser + BurpIA.jar"
    paso_simulado "Nessus + GVM/OpenVAS (servicios deshabilitados por defecto)"
    paso_simulado "enumerathor + Node.js 22 + chrome-devtools-mcp + computer-use-linux + opencode (DragonJAR provider)"
    exit 0
  fi
  instalar_herramientas
  resumen
  exit $(( PASOS_FALLIDOS > 0 ? 1 : 0 ))
}

modo_marca_usuario() {
  # Sin root (autostart o manual): reaplica la identidad del escritorio con los
  # assets persistidos; el avatar requiere root y quedó en la pasada completa
  if (( SIMULAR )); then
    paso_simulado "Tipografías del manual aplicadas a la sesión"
    paso_simulado "Terminal, panel, escritorio e iconos reaplicados"
    exit 0
  fi
  if ! _instalado "$DIR_ASSETS/isotipo-blanco.png"; then
    aviso "No hay marca instalada: ejecutá primero el script completo con sudo."
    exit 1
  fi
  # Si fase_marca (root) dejó /tmp/KALI-DSIO-marca root-owned, el rm/mkdir/cp
  # de este modo sin root falla con EACCES y la identidad se reaplica sin los
  # assets. Se usa un tmp propio del usuario en ese caso (no daña el root tmp).
  if [[ ! -w "$(dirname "$DIR_TMP_MARCA")" ]] || { [[ -e "$DIR_TMP_MARCA" ]] && [[ ! -w "$DIR_TMP_MARCA" ]]; }; then
    DIR_TMP_MARCA="/tmp/KALI-DSIO-marca-$(id -u)"
    info "tmp de marca root-owned en /tmp: usando $DIR_TMP_MARCA (usuario)"
  fi
  rm -rf "$DIR_TMP_MARCA"; mkdir -p "$DIR_TMP_MARCA"
  cp "$DIR_ASSETS/isotipo-blanco.png" "$DIR_TMP_MARCA/isotipo-blanco.png"
  if _instalado "$DIR_ASSETS/cabeza.png"; then
    cp "$DIR_ASSETS/cabeza.png" "$DIR_TMP_MARCA/cabeza.png"
  fi
  titulo_fase "Identidad DragonJAR · reaplicación"
  ejecutar "Aplicando tipografías del manual a la sesión" _opt_fuentes
  ejecutar "Aplicando terminal, panel, escritorio e iconos" _marca_usuario
  resumen
  exit $(( PASOS_FALLIDOS > 0 ? 1 : 0 ))
}
 
resumen() {
  _cerrar_linea
  printf '\n'
  separador
  printf '\n  %s═══════════ RESUMEN ═══════════%s\n\n' "$B" "$R"
  printf '    %s✓%s Completados : %-3d\n' "$VERDE$B" "$R" "$PASOS_OK"
  printf '    %s✗%s Fallidos    : %-3d\n' "$ROJO$B" "$R" "$PASOS_FALLIDOS"
  printf '    %s◦%s Simulados   : %-3d\n' "$GRIS$B" "$R" "$SIMULADOS"
  printf '    Registro: %s%s%s\n' "$DIM" "$REGISTRO" "$R"
  if (( PASOS_FALLIDOS > 0 )); then
    printf '\n  %sAcciones pendientes (revisar en el registro):%s\n' "$AMARILLO$B" "$R"
    local n; for n in "${NOMBRES_FALLIDOS[@]}"; do printf '    %s✗%s %s\n' "$ROJO" "$R" "$n"; done
    printf '    %s→%s Corregí y repetí: %ssudo %s %s\n' "$AZUL" "$R" "$B" "$0" "$R"
  else
    printf '\n  %s✓%s Sin errores: la preparación terminó correctamente.\n' "$VERDE$B" "$R"
  fi
  # Los pendientes de build (RAM/OVA) solo aplican a la corrida completa de la imagen
  if (( ! SOLO_MARCA )); then
    cat <<EOF
 
  ${B}Pendientes manuales (fuera de la VM):${R}
    1. Cambiar contraseñas:   passwd  ·  sudo passwd root
    2. Reiniciar:             activa teclado, tools de invitado y ajustes
    3. RAM a 4 GB:            Settings → Memory
    4. Compactar disco:       Settings → Hard Disk → Compact
    5. Exportar imagen:       File → Export to OVA

EOF
  fi
}
 
salir_interrumpido() {
  _cerrar_linea
  rm -rf -- "$DIR_TMP_MARCA" 2>/dev/null || true
  printf '\n  %sInterrumpido.%s Registro: %s\n' "$AMARILLO" "$R" "$REGISTRO"
  exit 130
}
trap salir_interrumpido INT TERM
 
bloquear_instancia "$@"
[[ -t 1 ]] && clear
encabezado
verificar_sistema
if (( ! SIMULAR && ! SOLO_MARCA )); then
  _preflight || exit 1
fi
info "Usuario: ${B}$USUARIO_REAL${R}   Equipo: ${B}$ETIQUETA_VIRT${R}   Modo: ${B}$([[ $SIMULAR -eq 1 ]] && echo 'SIMULACIÓN' || echo 'real')${R}"
(( SIMULAR )) && aviso "Modo simulación: no se modificará nada"
if [[ $SIMULAR -eq 0 ]] && [[ "$USUARIO_REAL" == "root" ]]; then
  aviso "Ejecutando como root sin SUDO_USER: los ajustes de usuario aplicarán al perfil de root."
fi
 
detectar_sesion_grafica
if (( SESION_GRAFICA )); then
  info "Sesión gráfica detectada: se aplicarán también los ajustes de escritorio"
else
  info "Sin sesión gráfica detectada: los pasos de escritorio se omitirán con seguridad"
fi

if (( SOLO_HERRAMIENTAS )); then
  modo_herramientas
fi

if (( SOLO_MARCA )); then
  modo_marca_usuario
fi
 
if [[ $SIMULAR -eq 0 ]]; then
  titulo_fase "Confirmación"
  info "Plan: cursor → idioma → teclado → actualización → tools de invitado →"
  info "      pipx/bbot → limpieza → optimización XFCE/zram → identidad DragonJAR"
  aviso "Se actualizará el sistema y se aplicará la identidad DragonJAR."
  aviso "El borrado de datos personales se vuelve a preguntar justo antes de ejecutarse."
  confirmar || { info "Cancelado por el usuario."; exit 130; }
fi
 
fase_cursor
fase_idioma
fase_teclado
fase_actualizacion
fase_herramientas
fase_pentest
fase_limpieza
fase_xfce
fase_marca
titulo_fase "Cierre · Higiene final para clonación"
fase_cierre
ejecutar "Marcando espacio libre (fstrim)" bash -c 'fstrim -av || echo "fstrim no soportado en este filesystem"'
resumen
exit $(( PASOS_FALLIDOS > 0 ? 1 : 0 ))
 
