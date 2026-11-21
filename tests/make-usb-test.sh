#!/usr/bin/env bash
# make-usb.sh --with-disk on the host (V080 stage C gate) – writes only files in a temporary
# directory, never a disk:
#
#   tests/make-usb-test.sh          all three parts below
#   ACCEL=kvm tests/make-usb-test.sh
#
# 1. Refusals: make-usb.sh --with-disk --dry-run against a fake /sys, /proc, lsblk and findmnt
#    (DESO_SYS / DESO_PROC, PATH): not USB, not removable, a partition instead of a disk,
#    a loop device, a mounted partition, swap on a partition, holders on the disk and on a
#    partition, larger than 256 GiB, 4096-byte sectors, a system disk, a wrong answer, the
#    device replaced between the question and the write, no serial number; and one that passes.
#    1b (v0.80.1): tools/mkusb.py's identity check of the opened device on a fake udev
#    directory (same, other serial, swapped, other size, no record / field, empty, twice), this
#    computer's USB disks (udev serial = lsblk's), and tools/mkdesofs.py – image files only
#    (new, non-empty without / with --force, a character / block device, a link to one, 65 GiB).
# 2. The image: make-usb.sh --with-disk --image (the code a real flash drive gets: tools/mkusb.py)
#    – GPT, the ESP checked by fsck.vfat when installed, BOOTX64.EFI read back; too small refused,
#    partition 2 never over 64 GiB.
# 3. The update: an image with build "v1" (self-test kernel) → start 1 (ONE STICK TEST part 1:
#    a file and the LKG written on /disk) → the ESP gets build "v2" (tools/mkusb.py --update-esp,
#    what `make-usb.sh /media/.../DESO` does on a mounted stick) → partition 2 the same byte
#    for byte → start 2 from the same image: `ver` = v2, the file and the LKG of start 1 there.
#    Two builds – so it is not part of every tests/test.sh run.  Ends with a plain
#    ./build.sh --selftest (no build tag).
set -uo pipefail

T="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$T")"
cd "$ROOT"

ACCEL="${ACCEL:-tcg}"
case "$ACCEL" in
  kvm) ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: kvm or tcg (got: $ACCEL)"; exit 3 ;;
esac
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
[ -f "$OVMF_CODE" ] || { echo "OVMF not found (sudo apt install ovmf)"; exit 3; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$ROOT/logs"
LOG="$ROOT/logs/test-make-usb.log"
: > "$LOG"
FAILS=0
PASSES=0
ok() { echo "[MAKE-USB TEST] $* PASS" | tee -a "$LOG"; PASSES=$((PASSES + 1)); }
bad() { echo "[MAKE-USB TEST] FAIL: $*" | tee -a "$LOG"; FAILS=$((FAILS + 1)); }

# ------------------------------------------------------------------ 1. refusals (fake system)
F="$W/fake"
mkdir -p "$F/bin"
cat > "$F/bin/lsblk" <<'EOF'
#!/usr/bin/env bash
# Fake lsblk: answers from files in $FAKE (one per column); SERIAL.2 = the serial from the
# second query on (a device replaced meanwhile).
dev="${@: -1}"
case "$*" in
  *"-no PKNAME"*) case "$dev" in /dev/sdz*) echo sdz ;; *) echo nvme0n1 ;; esac; exit 0 ;;
  *"-o NAME,SIZE"*) echo "sdz 4G"; exit 0 ;;
esac
col=""
for a in "$@"; do case "$a" in TYPE|TRAN|SERIAL|MAJ:MIN|MODEL|SIZE|MOUNTPOINTS|NAME|PARTTYPE) col="$a" ;; esac; done
case "$col" in
  SERIAL)
    n=$(( $(cat "$FAKE/serial.calls" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FAKE/serial.calls"
    if [ "$n" -ge 2 ] && [ -f "$FAKE/SERIAL.2" ]; then cat "$FAKE/SERIAL.2"; else cat "$FAKE/SERIAL"; fi ;;
  MAJ:MIN) cat "$FAKE/MAJMIN" ;;
  *) cat "$FAKE/$col" 2>/dev/null || true ;;
esac
EOF
cat > "$F/bin/findmnt" <<'EOF'
#!/usr/bin/env bash
cat "$FAKE/root_source" 2>/dev/null || echo /dev/nvme0n1p2
EOF
chmod +x "$F/bin/lsblk" "$F/bin/findmnt"

# A fresh fake system: a 4 GiB removable USB stick sdz with two partitions, nothing mounted.
fake_reset() {
  rm -rf "$F/sys" "$F/proc" "$F/state"
  mkdir -p "$F/sys/block/sdz/queue" "$F/sys/block/sdz/holders" "$F/sys/block/sdz/sdz1/holders" "$F/sys/block/sdz/sdz2/holders" "$F/proc" "$F/state"
  echo 1 > "$F/sys/block/sdz/removable"
  echo 512 > "$F/sys/block/sdz/queue/logical_block_size"
  printf 'Filename\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/nvme0n1p3 partition 8388604 0 -2\n' > "$F/proc/swaps"
  echo disk > "$F/state/TYPE"; echo usb > "$F/state/TRAN"; echo "SN1234" > "$F/state/SERIAL"
  echo "8:208" > "$F/state/MAJMIN"; echo "Fake Stick" > "$F/state/MODEL"; echo $((4 << 30)) > "$F/state/SIZE"
  : > "$F/state/MOUNTPOINTS"; printf 'sdz\nsdz1\nsdz2\n' > "$F/state/NAME"; : > "$F/state/PARTTYPE"
}
# Runs the dry run; $1 = the answer typed; output in $W/out, the exit code returned.
dry() {
  local answer="${1:-/dev/sdz}" dev="${2:-/dev/sdz}"
  rm -f "$F/state/serial.calls"
  printf '%s\n' "$answer" | FAKE="$F/state" DESO_SYS="$F/sys" DESO_PROC="$F/proc" PATH="$F/bin:$PATH" ./make-usb.sh --with-disk "$dev" --dry-run > "$W/out" 2>&1
}
refused() { # $1 = what, $2 = text the refusal must contain
  if dry "${3:-/dev/sdz}" "${4:-/dev/sdz}"; then bad "$1: not refused"; cat "$W/out" >> "$LOG"
  elif grep -q "$2" "$W/out"; then ok "refused - $1"
  else bad "$1: refused for another reason: $(tail -n1 "$W/out")"; fi
}
fake_reset; dry && grep -q "Dry run: all checks passed" "$W/out" && ok "a removable USB stick passes every check (dry run, nothing written)" || { bad "a good stick refused: $(tail -n1 "$W/out")"; }
fake_reset; echo sata > "$F/state/TRAN"; refused "not USB" "not attached via USB"
fake_reset; echo 0 > "$F/sys/block/sdz/removable"; refused "not removable" "not a removable disk"
fake_reset; echo part > "$F/state/TYPE"; refused "a partition instead of the disk" "not a whole disk" /dev/sdz1 /dev/sdz1
fake_reset; refused "a loop device" "not a physical disk" /dev/loop0 /dev/loop0
fake_reset; printf '\n/media/u/DESO\n' > "$F/state/MOUNTPOINTS"; refused "a mounted partition" "is mounted"
fake_reset; printf '/dev/sdz2 partition 1048572 0 -2\n' >> "$F/proc/swaps"; refused "swap on a partition" "swap area"
fake_reset; touch "$F/sys/block/sdz/holders/dm-0"; refused "a holder on the disk" "held by"
fake_reset; touch "$F/sys/block/sdz/sdz2/holders/dm-1"; refused "a holder on a partition (dm-crypt)" "held by"
fake_reset; echo $((300 << 30)) > "$F/state/SIZE"; refused "larger than 256 GiB" "larger than 256 GiB"
fake_reset; echo 4096 > "$F/sys/block/sdz/queue/logical_block_size"; refused "4096-byte sectors" "512-byte sectors only"
fake_reset; echo /dev/sdz1 > "$F/state/root_source"; refused "the system disk" "system disk"
fake_reset; refused "a wrong answer" "aborted - nothing changed" sdz
fake_reset; echo "OTHER99" > "$F/state/SERIAL.2"; refused "the device replaced between the question and the write" "changed since the question"
fake_reset; printf "c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n1a0e2e7d-de32-4c13-9442-9fcb2649ca02\n" > "$F/state/PARTTYPE"
dry && grep -q "YOUR DeSo OS DATA" "$W/out" && ok "an existing DeSo system partition is named before the question" || bad "no warning about an existing DeSo system partition"

fake_reset; : > "$F/state/SERIAL"; refused "a device without a serial number" "no serial number"

# ------------------------------------------------------------------ 1b. the writer's own checks (v0.80.1)
# tools/mkusb.py: the identity of the OPENED device – major:minor of the descriptor, size, and
# the serial number from the udev record of that major:minor (a fake udev directory here).
U="$W/udev"; mkdir -p "$U"
ident() { # $1 = what, $2 = expected result (ok / refused), $3.. = python arguments
  local what="$1" want="$2"; shift 2
  if python3 -c "
import os, sys
sys.path.insert(0, 'tools')
import mkusb
rdev, size, xr, xb, xs = sys.argv[1:6]
maj, mi = map(int, rdev.split(':'))
try:
    mkusb.check_identity(os.makedev(maj, mi), int(size), '$U', xr, int(xb), xs)
except mkusb.Fail as e:
    print(e); sys.exit(1)
" "$@" > "$W/out" 2>&1; then got=ok; else got=refused; fi
  if [ "$got" = "$want" ]; then ok "mkusb.py identity: $what -> $want"; else bad "mkusb.py identity: $what -> $got ($(cat "$W/out"))"; fi
}
printf 'S:disk/by-id/usb-Wilk\nE:ID_SERIAL_SHORT=SN1234\nE:ID_BUS=usb\n' > "$U/b8:208"
ident "the same device" ok 8:208 4294967296 8:208 4294967296 SN1234
ident "another stick with the same major:minor and size (other serial)" refused 8:208 4294967296 8:208 4294967296 SN9999
ident "the device number changed (swapped)" refused 8:224 4294967296 8:208 4294967296 SN1234
ident "another size" refused 8:208 4227858432 8:208 4294967296 SN1234
ident "no udev record" refused 8:240 4294967296 8:240 4294967296 SN1234
printf 'E:ID_BUS=usb\n' > "$U/b8:209"; ident "no serial field" refused 8:209 1 8:209 1 SN1234
printf 'E:ID_SERIAL_SHORT=\n' > "$U/b8:210"; ident "an empty serial" refused 8:210 1 8:210 1 SN1234
printf 'E:ID_SERIAL_SHORT=SN1234\nE:ID_SERIAL_SHORT=SN1234\n' > "$U/b8:211"; ident "the serial given twice" refused 8:211 1 8:211 1 SN1234
printf 'E:ID_SCSI_SERIAL=SCSI77\nE:ID_SERIAL_SHORT=SN1234\n' > "$U/b8:212"; ident "ID_SCSI_SERIAL first (as lsblk)" ok 8:212 1 8:212 1 SCSI77
ident "no expected serial" refused 8:208 4294967296 8:208 4294967296 ""
# This computer's USB disks: the serial mkusb.py reads must be the one lsblk (make-usb.sh) shows.
n=0
while read -r name tran; do
  [ "$tran" = "usb" ] || continue
  mm="$(lsblk -dno MAJ:MIN "/dev/$name" | tr -d ' ')"; ls_serial="$(lsblk -dno SERIAL "/dev/$name" | tr -d ' ')"
  [ -n "$ls_serial" ] || continue
  mine="$(python3 -c "import sys; sys.path.insert(0,'tools'); import mkusb; m,i=map(int,'$mm'.split(':')); print(mkusb.udev_serial(m,i))" 2>&1)"
  if [ "$mine" = "$ls_serial" ]; then ok "this computer: /dev/$name - the udev serial = lsblk's ($ls_serial)"; else bad "this computer: /dev/$name - udev gives '$mine', lsblk '$ls_serial'"; fi
  n=$((n + 1))
done < <(lsblk -dno NAME,TRAN 2>/dev/null)
[ "$n" -gt 0 ] || echo "[MAKE-USB TEST] no USB disk with a serial number attached - the udev / lsblk comparison skipped" | tee -a "$LOG"

# tools/mkdesofs.py: image files only.
M="$W/m.img"
mk() { python3 tools/mkdesofs.py "$@" > "$W/out" 2>&1; }
if mk "$M" --blocks 64; then ok "mkdesofs.py: a new image file"; else bad "mkdesofs.py: a new image: $(cat "$W/out")"; fi
before=$(sha256sum "$M" | cut -d' ' -f1)
if mk "$M"; then bad "mkdesofs.py: a non-empty image overwritten without --force"; elif [ "$(sha256sum "$M" | cut -d' ' -f1)" = "$before" ] && grep -q "add --force" "$W/out"; then ok "mkdesofs.py: a non-empty image refused without --force (unchanged)"; else bad "mkdesofs.py: refused, but the image changed / other reason: $(cat "$W/out")"; fi
if mk "$M" --force; then ok "mkdesofs.py: a non-empty image with --force"; else bad "mkdesofs.py: --force: $(cat "$W/out")"; fi
if mk /dev/null --force; then bad "mkdesofs.py: /dev/null (a character device) accepted"; elif grep -q "not a regular file" "$W/out"; then ok "mkdesofs.py: a character device refused (also with --force)"; else bad "mkdesofs.py: /dev/null: $(cat "$W/out")"; fi
ln -s /dev/null "$W/dev-link"
if mk "$W/dev-link" --force; then bad "mkdesofs.py: a link to a device accepted"; elif grep -q "not a regular file" "$W/out"; then ok "mkdesofs.py: a symbolic link to a device refused"; else bad "mkdesofs.py: link: $(cat "$W/out")"; fi
blk=""
for d in /dev/loop0 /dev/sda /dev/nvme0n1 /dev/vda; do [ -b "$d" ] && { blk="$d"; break; }; done
if [ -n "$blk" ]; then
  if mk "$blk" --force --blocks 64; then bad "mkdesofs.py: the block device $blk accepted"; elif grep -q "not a regular file" "$W/out"; then ok "mkdesofs.py: a block device ($blk) refused, also with --force - nothing opened for writing"; else bad "mkdesofs.py: $blk: $(cat "$W/out")"; fi
else
  echo "[MAKE-USB TEST] no block device found - the block device refusal skipped" | tee -a "$LOG"
fi
truncate -s 65G "$W/big65.img"
if mk "$W/big65.img" --force; then bad "mkdesofs.py: a 65 GiB volume accepted with --force"; elif grep -q "larger than 64 GiB" "$W/out" && [ -z "$(head -c 65536 "$W/big65.img" | tr -d '\0' | head -c1)" ]; then ok "mkdesofs.py: 65 GiB refused also with --force, nothing written"; else bad "mkdesofs.py: 65 GiB: $(cat "$W/out")"; fi
rm -f "$W/big65.img"
if mk "$W/nonew.img"; then bad "mkdesofs.py: a new image without --blocks accepted"; elif [ ! -e "$W/nonew.img" ]; then ok "mkdesofs.py: a new image without --blocks refused, no file left"; else bad "mkdesofs.py: a refused new image left a file"; fi

# ------------------------------------------------------------------ 2. the image
echo "[MAKE-USB TEST] building the self-test kernel, build v1..." | tee -a "$LOG"
DESO_BUILD_TAG=v1 ./build.sh --selftest > "$W/build1.log" 2>&1 || { tail -n 20 "$W/build1.log"; bad "build v1"; exit 1; }
cp build/EFI/BOOT/BOOTX64.EFI "$W/v1.efi"
IMG="$W/stick.img"
if ./make-usb.sh --with-disk --image "$IMG" 256 --efi "$W/v1.efi" >> "$LOG" 2>&1 && python3 tools/mkusb.py --verify "$IMG" --efi "$W/v1.efi" >> "$LOG" 2>&1; then
  ok "make-usb.sh --with-disk --image: GPT (both headers), ESP with BOOTX64.EFI, DeSoFS - read back"
else
  bad "make-usb.sh --with-disk --image"
fi
if command -v fsck.vfat > /dev/null; then
  dd if="$IMG" of="$W/esp.img" bs=512 skip=2048 count=262144 status=none
  if fsck.vfat -n "$W/esp.img" >> "$LOG" 2>&1; then ok "fsck.vfat: the ESP is a clean FAT32"; else bad "fsck.vfat found errors in the ESP"; fi
else
  echo "[MAKE-USB TEST] fsck.vfat not installed (dosfstools) - FAT check skipped" | tee -a "$LOG"
fi
for small in 150; do
  if ./make-usb.sh --with-disk --image "$W/small.img" "$small" --efi "$W/v1.efi" > "$W/out" 2>&1; then bad "a $small MiB image accepted"
  else ok "a $small MiB image refused (ESP 128 MiB + DeSo system 64 MiB)"; fi
done

# A 70000 MiB stick (a sparse file): partition 2 exactly 64 GiB, the rest unallocated and said so.
if ./make-usb.sh --with-disk --image "$W/big.img" 70000 --efi "$W/v1.efi" > "$W/out" 2>&1 && grep -q "DeSo system 65536 MiB" "$W/out" && grep -q "left unallocated" "$W/out"; then
  ok "a 70000 MiB stick: partition 2 = 64 GiB, the rest unallocated (reported)"
else
  bad "a 70000 MiB stick: $(grep mkusb "$W/out" | head -n 2 | tr '\n' ' ')"
fi
rm -f "$W/big.img"

# ------------------------------------------------------------------ 3. the update
qemu_start() { # $1 = phase, $2 = log
  timeout 300 qemu-system-x86_64 -machine q35 -m 512M -smp 2 "${ACCEL_ARGS[@]}" \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -device qemu-xhci,id=xhci \
    -drive if=none,id=stick,format=raw,file="$IMG" \
    -device usb-storage,bus=xhci.0,port=1,drive=stick,bootindex=0 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -fw_cfg name=opt/deso/autotest,string=1 \
    -fw_cfg "name=opt/deso/phase,string=$1" \
    -serial stdio -display none -no-reboot < /dev/null > "$2" 2>&1
}
p2_sum() { python3 - "$IMG" <<'EOF'
import hashlib, struct, sys
f = open(sys.argv[1], "rb"); f.seek(512 + 72); tlba = struct.unpack("<Q", f.read(8))[0]
f.seek(tlba * 512 + 128 + 32); a, b = struct.unpack("<QQ", f.read(16))
f.seek(a * 512); h = hashlib.sha256()
left = (b - a + 1) * 512
while left:
    c = f.read(min(left, 1 << 22)); h.update(c); left -= len(c)
print(h.hexdigest())
EOF
}
qemu_start "onestick1 v1" "$W/start1.log"; c=$?
grep -a "ONE STICK TEST\] 1/2\|ONE STICK TEST\] FAIL" "$W/start1.log" | tr -d '\r' >> "$LOG"
if [ "$c" = 33 ]; then ok "start 1 from the image (build v1): /usb0 ESP read-only, /disk read-write, file and LKG written"
else bad "start 1 from the image: QEMU code $c"; tail -n 15 "$W/start1.log" >> "$LOG"; fi
P2_BEFORE=$(p2_sum)
echo "[MAKE-USB TEST] building the self-test kernel, build v2..." | tee -a "$LOG"
DESO_BUILD_TAG=v2 ./build.sh --selftest > "$W/build2.log" 2>&1 || { tail -n 20 "$W/build2.log"; bad "build v2"; exit 1; }
cp build/EFI/BOOT/BOOTX64.EFI "$W/v2.efi"
cmp -s "$W/v1.efi" "$W/v2.efi" && bad "builds v1 and v2 are the same file"
if python3 tools/mkusb.py --update-esp "$IMG" --efi "$W/v2.efi" >> "$LOG" 2>&1 && [ "$(p2_sum)" = "$P2_BEFORE" ]; then
  ok "the ESP updated to build v2, partition 2 (DeSoFS) the same byte for byte"
else
  bad "update of the ESP / partition 2 changed"
fi
qemu_start "onestick2 v2" "$W/start2.log"; c=$?
grep -a "ONE STICK TEST\] 2/2\|ONE STICK TEST\] FAIL" "$W/start2.log" | tr -d '\r' >> "$LOG"
if [ "$c" = 33 ]; then ok "start 2 from the updated image: build v2 runs, the file and the LKG of start 1 there"
else bad "start 2 from the updated image: QEMU code $c"; tail -n 15 "$W/start2.log" >> "$LOG"; fi

echo "[MAKE-USB TEST] the self-test kernel again without a build tag..." | tee -a "$LOG"
./build.sh --selftest > "$W/build3.log" 2>&1 || { tail -n 20 "$W/build3.log"; bad "build without a tag"; }

echo "Log: logs/test-make-usb.log"
if [ "$FAILS" = 0 ]; then
  echo "PASS - make-usb test: $PASSES checks PASSED"
  exit 0
fi
echo "FAIL - make-usb test: $FAILS failed, $PASSES passed"
exit 1
