#!/usr/bin/env bash
# =============================================================================
# ip-bootstrap.sh — 新机器开荒脚本（交互式）
# 适用：Debian 12 / Ubuntu 22.04 / 24.04，root 权限
# 风格与 ip-cert-acme.sh 保持一致：函数化、幂等可重跑、危险操作自带安全网
# 用法：bash ip-bootstrap.sh
# =============================================================================
set -u
VERSION="0.3.0"

# ---------- 颜色与日志 ----------
C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_CYAN='\033[0;36m'; C_RESET='\033[0m'
info()  { printf '%b[信息]%b %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%b[警告]%b %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
error() { printf '%b[错误]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()   { error "$*"; exit 1; }
pause() { printf '%b按回车继续...%b' "$C_CYAN" "$C_RESET"; read -r _; }
confirm() { # $1=提示语，默认 Y
  local prompt="${1:-继续?}" ans
  printf '%b%s [Y/n]%b ' "$C_YELLOW" "$prompt" "$C_RESET"
  read -r ans; [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]
}

# ---------- 环境检查 ----------
require_root() { [[ $EUID -eq 0 ]] || die "需要 root 权限，请用 sudo 运行。"; }
require_tty()  { [[ -t 0 ]] || die "请在交互式终端中运行（不要用管道/重定向 stdin）。"; }
detect_os() {
  local id
  id=$(. /etc/os-release && echo "$ID")
  case "$id" in
    debian|ubuntu) OS_FAMILY="$id" ;;
    *) die "仅支持 Debian/Ubuntu，检测到 $id。其他发行版请自行审阅后修改。";;
  esac
  info "系统识别：$OS_FAMILY $(. /etc/os-release && echo "$VERSION_ID")"
}

# ---------- 通用工具 ----------
current_ssh_port() {
  local p
  p=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')
  [[ -n "$p" ]] || p=$(grep -E '^#?Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1)
  echo "${p:-22}"
}
my_ip() { # 当前 SSH 连接来源 IP（fail2ban 白名单用）
  echo "${SSH_CLIENT:-$(who -m 2>/dev/null | awk '{print $NF}' | tr -d '()')}" | awk '{print $1}'
}
ssh_dir() { # 目标用户家目录：root -> /root，其他 -> /home/$1
  [[ "$1" == "root" ]] && echo /root || echo /home/"$1"
}
validate_pubkey() { # $1=公钥字符串
  local type part
  type=$(echo "$1" | awk '{print $1}')
  part=$(echo "$1" | awk '{print $2}')
  case "$type" in
    ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)
      [[ ${#part} -gt 40 ]] ;;
    *) false ;;
  esac
}
install_pkgs() { # 幂等安装，失败即停
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y "$@" >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y "$@" >/dev/null 2>&1; } || die "软件包安装失败: $*"
}

# =============================================================================
# 01 系统基础：更新软件 / 基础工具 / 主机名
# =============================================================================
setup_system_basics() {
  info "== 系统基础 =="
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || die "apt update 失败，请检查网络与软件源"
  apt-get upgrade -y -qq || warn "apt upgrade 部分包升级失败（可稍后重试）"
  apt-get autoremove -y -qq >/dev/null 2>&1
  install_pkgs curl wget git vim htop tmux unzip rsync jq ca-certificates
  info "基础工具已就绪"
  local hn
  read -rp "设置主机名（当前: $(hostname)，留空跳过）: " hn
  if [[ -n "$hn" ]]; then
    hostnamectl set-hostname "$hn" && info "主机名已设为 $hn"
  fi
  return 0
}

# =============================================================================
# 02 时区与时间同步（chrony / systemd-timesyncd 二选一）
# =============================================================================
setup_timezone() {
  info "== 时区与时间同步 =="
  local tz
  read -rp "时区（默认 Asia/Shanghai，留空用默认）: " tz
  timedatectl set-timezone "${tz:-Asia/Shanghai}" && info "时区: $(timedatectl show -p Timezone --value)"
  if systemctl is-active systemd-timesyncd >/dev/null 2>&1; then
    timedatectl set-ntp true && info "已启用 systemd-timesyncd 时间同步"
  else
    install_pkgs chrony
    systemctl enable --now chrony >/dev/null 2>&1 && info "已安装并启用 chrony"
  fi
  timedatectl set-local-rtc 0 2>/dev/null || true
  warn "若云厂商要求使用其时间源，请自行修改 chrony/ntp 配置"
  return 0
}

# =============================================================================
# 03 粘贴公钥到 root（只允许密钥登录的前提，先种钥匙）
# =============================================================================
add_pubkey_to() { # $1=用户, $2=公钥内容
  local dir kfile
  dir=$(ssh_dir "$1")
  mkdir -p "$dir/.ssh" && chmod 700 "$dir/.ssh"
  kfile="$dir/.ssh/authorized_keys"
  touch "$kfile" && chmod 600 "$kfile" && chown -R "${1}:${1}" "$dir/.ssh" 2>/dev/null
  if grep -qF "$2" "$kfile"; then
    warn "公钥已存在，跳过：${2:0:40}..."
    return 0
  fi
  echo "$2" >> "$kfile" && info "已添加公钥到 $kfile"
}
setup_root_key() {
  info "== 粘贴公钥到 root =="
  local dir=/root/.ssh kf line
  mkdir -p "$dir" && chmod 700 "$dir"
  touch "$dir/authorized_keys" && chmod 600 "$dir/authorized_keys"
  read -rp "公钥文件路径（如 ~/.ssh/id_ed25519.pub，留空改为直接粘贴）: " kf
  if [[ -n "$kf" && -f "$kf" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" && "${line:0:1}" != "#" ]] && { validate_pubkey "$line" && add_pubkey_to root "$line" || warn "跳过非法公钥行"; }
    done < "$kf"
  else
    info "逐行粘贴公钥（ssh-ed25519 AAAA...），空行结束："
    while IFS= read -r line; do
      [[ -z "$line" ]] && break
      validate_pubkey "$line" && add_pubkey_to root "$line" || warn "公钥格式不合法，已跳过"
    done
  fi
  if [[ -s "$dir/authorized_keys" ]]; then
    info "root 公钥配置完成（$(wc -l < "$dir/authorized_keys") 条）"
  else
    warn "未添加任何公钥！后续 SSH 加固会被拒绝执行"
  fi
  return 0
}

# =============================================================================
# 04 防火墙：探测 firewalld / ufw，放行端口
# =============================================================================
FIREWALL_TOOL=""
init_firewall_tool() { # 探测防火墙工具（不启用、不改规则）
  if systemctl is-active firewalld >/dev/null 2>&1; then
    FIREWALL_TOOL=firewalld
  elif command -v ufw >/dev/null 2>&1 || systemctl list-unit-files 2>/dev/null | grep -q '^ufw'; then
    FIREWALL_TOOL=ufw
  else
    FIREWALL_TOOL=""
  fi
}
open_port() { # $1=端口, $2=tcp|udp（幂等）
  case "$FIREWALL_TOOL" in
    firewalld) firewall-cmd --permanent --add-port="$1/$2" >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1 ;;
    ufw)       ufw allow "$1/$2" >/dev/null 2>&1 ;;
  esac
}
setup_firewall() {
  info "== 防火墙 =="
  local sshport="${SSH_PORT:-$(current_ssh_port)}"
  init_firewall_tool
  if [[ "$FIREWALL_TOOL" == "firewalld" ]]; then
    info "检测到 firewalld，使用 firewall-cmd"
  else
    FIREWALL_TOOL=ufw
    command -v ufw >/dev/null 2>&1 || install_pkgs ufw
    info "使用 ufw"
  fi
  # 端口清单：先显式放行当前 SSH 端口，再追加用户输入；精确 token 去重（不用子串，防 22/2222 误判）
  local extra p
  read -rp "额外放行端口（逗号分隔，默认 80,443; 当前 SSH 端口 ${sshport} 会自动放行）: " extra
  local -a plist=()
  IFS=',' read -ra tmp <<< "${sshport},${extra:-80,443}"
  for p in "${tmp[@]}"; do
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    [[ " ${plist[*]} " == *" $p "* ]] || plist+=("$p")
  done
  for p in "${plist[@]}"; do
    open_port "$p" tcp && info "已放行 TCP $p"
  done
  if [[ "$FIREWALL_TOOL" == "ufw" ]]; then
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    if ufw status | grep -q "Status: active"; then
      info "ufw 已启用"
    else
      ufw --force enable >/dev/null 2>&1 && info "ufw 已启用（默认拒绝入站）"
    fi
  fi
  warn "云安全组是厂商侧资源，脚本管不到：请到云控制台同步放行: ${plist[*]}"
  return 0
}

# =============================================================================
# 05 修改 SSH 端口（安全网：先放行 → 备份 → 变更 → 校验 → 探测 → 失败回滚）
# =============================================================================
change_ssh_port() {
  info "== 修改 SSH 端口 =="
  local cur new
  cur=$(current_ssh_port)
  read -rp "当前 SSH 端口: $cur，输入新端口（留空跳过）: " new
  [[ -n "$new" ]] || { info "跳过"; return 0; }
  [[ "$new" =~ ^[0-9]+$ && "$new" -ge 1 && "$new" -le 65535 ]] || die "端口不合法: $new"
  [[ "$new" -ne "$cur" ]] || { info "端口未变化，跳过"; return 0; }

  # 1) 防火墙先放行新端口：启用中则强制放行，禁止跳过（本地探测过不了防火墙，必须在这里堵住）
  init_firewall_tool
  if [[ "$FIREWALL_TOOL" == "firewalld" ]] && systemctl is-active firewalld >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$new/tcp" >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
    info "firewalld 已放行 TCP $new"
  elif [[ "$FIREWALL_TOOL" == "ufw" ]] && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$new/tcp" >/dev/null 2>&1
    info "ufw 已放行 TCP $new"
  else
    warn "防火墙未启用，跳过放行（之后启用防火墙时请记得放行 $new）"
  fi

  # 2) 备份
  local bak
  bak="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
  cp /etc/ssh/sshd_config "$bak" || die "备份 sshd_config 失败，中止"

  # 3) 写入新端口（幂等替换）
  if grep -qE '^#?Port ' /etc/ssh/sshd_config; then
    sed -i "s/^#\?Port .*/Port $new/" /etc/ssh/sshd_config
  else
    echo "Port $new" >> /etc/ssh/sshd_config
  fi

  # 4) 配置校验 + 重载（失败即回滚）
  if ! sshd -t; then
    cp "$bak" /etc/ssh/sshd_config
    die "sshd 配置校验失败，已回滚原配置"
  fi
  systemctl reload ssh >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || { cp "$bak" /etc/ssh/sshd_config; systemctl restart ssh >/dev/null 2>&1; die "sshd 重载失败，已回滚"; }
  sleep 1

  # 5) 本地探测新端口
  if (command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$new") || ss -tln | grep -q ":$new "; then
    info "验证通过：新端口 $new 已监听"
  else
    warn "未探测到新端口监听，自动回滚..."
    cp "$bak" /etc/ssh/sshd_config
    systemctl restart ssh >/dev/null 2>&1
    die "已回滚，SSH 端口仍为 $cur"
  fi

  # 6) 收尾提示
  SSH_PORT="$new"
  warn "本会话不会断开。请务必开新终端用 $new 登录验证（本地探测通过 ≠ 云安全组已放行）"
  return 0
}

# =============================================================================
# 06 fail2ban：安装 + sshd jail + 白名单
# =============================================================================
setup_fail2ban() {
  info "== fail2ban =="
  if systemctl is-active fail2ban >/dev/null 2>&1; then
    info "fail2ban 已在运行，跳过安装"
  else
    install_pkgs fail2ban
  fi
  local myip sshport
  myip=$(my_ip)
  sshport="${SSH_PORT:-$(current_ssh_port)}"
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 ${myip}
bantime  = 10m
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = ${sshport}
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1
  systemctl restart fail2ban >/dev/null 2>&1 || warn "fail2ban 启动失败，请查看 journalctl -u fail2ban"
  info "fail2ban 已启用（白名单含当前连接 IP: ${myip:-无}，监控端口 ${sshport}）"
  fail2ban-client status sshd 2>/dev/null | grep -E "Currently banned|Total banned" | sed 's/^/  /' || true
  return 0
}

# =============================================================================
# 07 SSH 安全加固（须在公钥配置成功后执行，防锁死）
# =============================================================================
harden_ssh() {
  info "== SSH 安全加固 =="
  # 前置检查：root 必须已有公钥（防止禁密码后把自己锁死）
  [[ -s /root/.ssh/authorized_keys ]] || die "root 尚未配置公钥！请先执行菜单 [3] 粘贴公钥，否则会把自己锁死"

  local bak
  bak="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
  cp /etc/ssh/sshd_config "$bak" || die "备份 sshd_config 失败，中止"
  sed -i \
    -e 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' \
    -e 's/^#\?PermitRootLogin .*/PermitRootLogin prohibit-password/' \
    -e 's/^#\?MaxAuthTries .*/MaxAuthTries 3/' \
    -e 's/^#\?ClientAliveInterval .*/ClientAliveInterval 300/' \
    -e 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/' \
    /etc/ssh/sshd_config
  # 确保关键项存在（若原本被注释/缺失）
  grep -q '^PasswordAuthentication '   /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
  grep -q '^PermitRootLogin '           /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
  grep -q '^MaxAuthTries '              /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config

  if ! sshd -t; then
    cp "$bak" /etc/ssh/sshd_config
    die "sshd 配置校验失败，已回滚原配置（连接未中断）"
  fi
  systemctl reload ssh >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || { cp "$bak" /etc/ssh/sshd_config; systemctl restart ssh >/dev/null 2>&1; die "sshd 重载失败，已回滚"; }
  info "已生效：root 仅允许密钥登录 / 禁止密码登录 / MaxAuthTries=3"
  warn "本会话保持连接。请务必先开新终端验证密钥登录正常，再关闭当前会话"
  return 0
}

# =============================================================================
# 08 系统优化：swap / BBR / 自动安全更新
# =============================================================================
setup_swap() {
  swapon --show | grep -q . && { info "已有 swap，跳过"; return 0; }
  info "创建 1G swapfile..."
  fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 >/dev/null 2>&1
  chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile || die "swap 创建失败"
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
  sysctl -w vm.swappiness=10 >/dev/null 2>&1
  info "swap 已启用（1G，swappiness=10）"
}
enable_bbr() {
  local major minor
  major=$(uname -r | cut -d. -f1); minor=$(uname -r | cut -d. -f2)
  if [[ "$major" -lt 4 ]] || { [[ "$major" -eq 4 ]] && [[ "$minor" -lt 9 ]]; }; then
    warn "内核 $(uname -r) 低于 4.9，跳过 BBR"; return 0
  fi
  cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
  info "TCP 拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
}
setup_unattended() {
  install_pkgs unattended-upgrades
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  info "已启用自动安全更新（unattended-upgrades）"
}
setup_journal_limit() { # journald 日志限额，防小机器日志撑爆磁盘
  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/99-size.conf <<'EOF'
SystemMaxUse=200M
EOF
  systemctl restart systemd-journald >/dev/null 2>&1 || true
  info "journald 日志上限已限制为 200M"
}
setup_tune() {
  info "== 系统优化 =="
  setup_swap
  enable_bbr
  setup_unattended
  setup_journal_limit
  return 0
}

# =============================================================================
# 09 挂载数据盘（云服务器裸盘 → 挂载点，写入 fstab）
# =============================================================================
mount_data_disk() {
  info "== 挂载数据盘 =="
  echo "当前磁盘状况："
  lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null || die "lsblk 不可用"
  local dev mnt uuid
  read -rp "输入要挂载的裸盘/分区设备（如 /dev/vdb 或 /dev/vdb1，留空跳过）: " dev
  [[ -n "$dev" ]] || { info "跳过"; return 0; }
  [[ -b "$dev" ]] || die "设备不存在: $dev"
  lsblk -no MOUNTPOINTS "$dev" 2>/dev/null | grep -q . && die "$dev 已在挂载中"
  read -rp "挂载点（默认 /data）: " mnt
  mnt="${mnt:-/data}"
  [[ "$mnt" == /* ]] || die "挂载点必须是绝对路径: $mnt"
  [[ -d "$mnt" ]] || mkdir -p "$mnt"
  # 无分区表的裸盘：确认后格式化为 ext4（数据清空！）
  if [[ "$(lsblk -no NAME "$dev" | wc -l)" -eq 1 ]]; then
    confirm "设备 $dev 无分区表，将格式化为 ext4（原有数据会清空），继续?" || { info "已取消"; return 0; }
    mkfs.ext4 -F "$dev" >/dev/null 2>&1 || die "格式化 $dev 失败"
  fi
  uuid=$(blkid -s UUID -o value "$dev" 2>/dev/null)
  [[ -n "$uuid" ]] || uuid=$(blkid -s UUID -o value "${dev}1" 2>/dev/null)
  [[ -n "$uuid" ]] || die "无法获取 UUID（设备是否已分区？）"
  grep -q "$uuid" /etc/fstab || echo "UUID=$uuid $mnt ext4 defaults 0 2" >> /etc/fstab
  mount -a && info "已挂载 → $mnt（UUID 写入 fstab）" || die "挂载失败，请检查 fstab"
  df -h "$mnt" | tail -1
  return 0
}

# =============================================================================
# 10 环境体检报告（开荒前后状态对比）
# =============================================================================
env_report() {
  info "======== 环境体检报告 ========"
  printf '%-20s %s\n' "系统:"      "$(. /etc/os-release && echo "$PRETTY_NAME")"
  printf '%-20s %s\n' "内核:"      "$(uname -r)"
  printf '%-20s %s\n' "CPU:"       "$(nproc) 核"
  printf '%-20s %s\n' "内存:"      "$(free -h | awk '/^Mem:/{print $2" 总量 / "$3" 已用"}')"
  printf '%-20s %s\n' "swap:"      "$(free -h | awk '/^Swap:/{print $2" 总量 / "$3" 已用"}')"
  printf '%-20s %s\n' "磁盘( / ):" "$(df -h / | awk 'NR==2{print $2" 总量 / "$3" 已用 / "$5" 使用率"}')"
  printf '%-20s %s\n' "时区:"      "$(timedatectl show -p Timezone --value 2>/dev/null || echo 未知)"
  printf '%-20s %s\n' "时间同步:"  "$(timedatectl status 2>/dev/null | grep -i 'NTP synchronized' | awk -F': ' '{print $2}')"
  printf '%-20s %s\n' "SSH 端口:"  "$(current_ssh_port)"
  printf '%-20s %s\n' "SSH 密码登录:" "$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')"
  printf '%-20s %s\n' "root 公钥:" "$(if [[ -s /root/.ssh/authorized_keys ]]; then echo "已配置 ($(wc -l < /root/.ssh/authorized_keys) 条)"; else echo "未配置"; fi)"
  printf '%-20s %s\n' "防火墙:"    "$(if ufw status 2>/dev/null | grep -q 'Status: active'; then echo 'ufw active'; else echo 'ufw inactive / 未装'; fi)"
  printf '%-20s %s\n' "fail2ban:"  "$(systemctl is-active fail2ban 2>/dev/null || echo 未安装)"
  printf '%-20s %s\n' "BBR:"       "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 未启用)"
  printf '%-20s %s\n' "自动更新:"  "$(systemctl is-enabled unattended-upgrades 2>/dev/null || echo 未启用)"
  printf '%-20s %s\n' "失败服务:"  "$(systemctl --failed --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
  echo "----------------------------------------"
  return 0
}

# =============================================================================
# 一键全流程（严格按安全顺序）
# =============================================================================
full_wizard() {
  info "======== 全流程开荒开始 ========"
  # 前置检查 1：root 必须有公钥（防止开荒到一半被锁死 / 流程半途失败）
  if [[ ! -s /root/.ssh/authorized_keys ]]; then
    warn "root 尚未配置公钥，先执行公钥粘贴..."
    setup_root_key || return 1
  fi
  # 前置检查 2：探测防火墙工具，供后续改端口时强制放行
  init_firewall_tool

  setup_system_basics
  setup_timezone
  setup_root_key
  setup_firewall
  change_ssh_port
  # 危险衔接：改完端口必须人工确认新端口外部可用，才允许继续禁密码
  if ! confirm "SSH 端口变更完成。请开新终端用新端口验证可登录。确认已通过?"; then
    warn "已暂停。请自行验证新端口，之后可单独执行 [7] 完成 SSH 加固"
    return 0
  fi
  setup_fail2ban
  harden_ssh
  setup_tune
  info "======== 开荒完成 ========"
  warn "建议 reboot 使内核/挂载变更完全生效（重启前请确认新 SSH 端口可登录）"
}

# =============================================================================
# 外部工具快捷方式（第三方远端脚本）
# 风险说明：curl|bash 会把 root 权限交给第三方脚本作者，属供应链信任模型，
# 执行前要求输入 YES 二次确认并展示来源 URL。
# =============================================================================
run_external() { # $1=名称, $2=来源URL
  local name="$1" url="$2" ans
  warn "即将执行第三方远端脚本：$name"
  info  "脚本来源: $url"
  warn "该脚本内容由第三方控制，将以 root 权限直接运行，存在供应链风险（投毒/劫持），执行前请确认来源可信"
  read -rp "输入 YES 确认执行（其他任意键取消）: " ans
  [[ "$ans" == "YES" ]] || { info "已取消"; return 0; }
  bash <(curl -fsSL "$url") && info "$name 执行完毕" || warn "$name 执行异常（网络或脚本问题）"
}
run_nodequality() {
  run_external "NodeQuality 节点质量测试" "https://run.NodeQuality.com"
}
run_tcpquality() {
  local c
  echo " 1) GitHub Raw（国外服务器推荐）"
  echo " 2) 加速入口（国内服务器推荐）"
  read -rp "选择入口 [1/2]: " c
  case "$c" in
    2) run_external "TcpQuality 测试（加速入口）" "https://tcpquality.ibsgss.uk/run" ;;
    *) run_external "TcpQuality 测试（GitHub Raw）" "https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality.sh" ;;
  esac
}

# =============================================================================
# 主菜单
# =============================================================================
show_menu() {
  printf '\n%b==========================================%b\n' "$C_CYAN" "$C_RESET"
  printf '%b  新机器开荒脚本 ip-bootstrap.sh  v%s%b\n' "$C_CYAN" "$VERSION" "$C_RESET"
  printf '%b  系统: %s   SSH 端口: %s%b\n' "$C_CYAN" "${OS_FAMILY:-?}" "$(current_ssh_port)" "$C_RESET"
  printf '%b==========================================%b\n' "$C_CYAN" "$C_RESET"
  echo " 1) 系统基础：更新软件 / 工具 / 主机名"
  echo " 2) 时区与时间同步"
  echo " 3) 粘贴公钥到 root（SSH 加固的前提）"
  echo " 4) 防火墙安装与放行端口"
  echo " 5) 修改 SSH 端口（安全网保护）"
  echo " 6) 安装 fail2ban（自动匹配 SSH 端口）"
  echo " 7) SSH 加固：root 仅密钥 / 禁止密码登录"
  echo " 8) 系统优化：swap / BBR / 自动更新 / 日志限额"
  echo " 9) 挂载数据盘"
  echo "10) 环境体检报告"
  echo "11) 一键全流程开荒（安全顺序）"
  echo "----------------------------------------"
  echo "12) NodeQuality 节点质量测试（第三方脚本）"
  echo "13) TcpQuality TCP 质量测试（第三方脚本）"
  echo " 0) 退出"
  printf '%b请选择 [0-13]: %b' "$C_YELLOW" "$C_RESET"
}
main() {
  require_root
  require_tty
  detect_os
  local choice
  while true; do
    show_menu
    read -r choice
    case "$choice" in
      1) setup_system_basics ;;
      2) setup_timezone ;;
      3) setup_root_key ;;
      4) setup_firewall ;;
      5) change_ssh_port ;;
      6) setup_fail2ban ;;
      7) harden_ssh ;;
      8) setup_tune ;;
      9) mount_data_disk ;;
      10) env_report ;;
      11) full_wizard ;;
      12) run_nodequality ;;
      13) run_tcpquality ;;
      0) info "再见"; exit 0 ;;
      *) warn "无效选择: $choice" ;;
    esac
    pause
  done
}
main "$@"
