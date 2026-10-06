#!/bin/sh
set -ex

echo "[+] Initialize"
GDBINIT_PATH="/root/.gdbinit"
GEF_DIR="/root/.gef"
GEF_PKGDIR="${GEF_DIR}/gef"
GEF_REPO="MarcoApollonio02/gef"
GEF_REF="dev"
GEF_ARCHIVE_URL="https://github.com/${GEF_REPO}/archive/refs/heads/${GEF_REF}.tar.gz"

echo "[+] User check"
if [ "$(id -u)" != "0" ]; then
    echo "[-] Detected non-root user."
    echo "[-] INSTALLATION FAILED"
    exit 1
fi

echo "[+] Check if another gef is installed"
if [ -e "${GEF_PKGDIR}" ]; then
    echo "[-] ${GEF_PKGDIR} already exists. Please delete or rename."
    echo "[-] INSTALLATION FAILED"
    exit 1
fi

echo "[+] Create .gef directory"
if [ ! -e "${GEF_DIR}" ]; then
    mkdir -p "${GEF_DIR}"
fi

echo "[+] Download gef"
TMPDIR_GEF="$(mktemp -d)"
wget -q "${GEF_ARCHIVE_URL}" -O "${TMPDIR_GEF}/gef.tar.gz"
if [ ! -s "${TMPDIR_GEF}/gef.tar.gz" ]; then
    echo "[-] Downloading ${GEF_ARCHIVE_URL} failed."
    rm -rf "${TMPDIR_GEF}"
    echo "[-] INSTALLATION FAILED"
    exit 1
fi
tar -xzf "${TMPDIR_GEF}/gef.tar.gz" -C "${TMPDIR_GEF}"
GEF_SRC="$(find "${TMPDIR_GEF}" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
rm -rf "${GEF_PKGDIR}"
cp -r "${GEF_SRC}/gef" "${GEF_PKGDIR}"
cp "${GEF_SRC}/gef-bootstrap.py" "${GEF_DIR}/gef-bootstrap.py"
rm -f "${GEF_DIR}/gef.py"
sha512sum "${TMPDIR_GEF}/gef.tar.gz" | awk '{print $1}' > "${GEF_DIR}/.gef-archive.sha512"
rm -rf "${TMPDIR_GEF}"

echo "[+] Setup gef"
STARTUP_COMMAND="python sys.path.insert(0, \"${GEF_DIR}\"); from gef import *; Gef.main()"
if [ ! -e "${GDBINIT_PATH}" ] || [ -z "$(grep "from gef import" "${GDBINIT_PATH}")" ]; then
    echo "${STARTUP_COMMAND}" >> "${GDBINIT_PATH}"
fi

echo "[+] INSTALLATION SUCCESSFUL"
exit 0
