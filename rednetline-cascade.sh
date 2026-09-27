#!/usr/bin/env bash
# shellcheck shell=bash
# =============================================================================
#  Rednetline Cascade
#  Каскадная переадресация трафика на VPS: DNAT + MASQUERADE через iptables.
#
#  Схема:  клиент  ->  [этот VPS: DNAT]  ->  зарубежный сервер
#
#  Сценарии: AmneziaWG / WireGuard (UDP), VLESS / XRay (TCP), MTProto (TCP),
#            произвольные TCP/UDP-сервисы, в том числе с разными портами
#            входа и выхода (проброс SSH, RDP и т.п.).
#
#  Версия: 3.0.0
#  Лицензия: MIT
# =============================================================================

set -euo pipefail

# --- КОНФИГУРАЦИЯ (можно переопределить переменными окружения) ---------------
APP_NAME="Rednetline Cascade"
APP_VERSION="3.0.0"

APP_BIN="${RLN_BIN:-/usr/local/bin/rednetline}"
CONF_DIR="${RLN_CONF_DIR:-/etc/rednetline-cascade}"
STATE_FILE="$CONF_DIR/rules.conf"
LOG_FILE="${RLN_LOG:-/var/log/rednetline-cascade.log}"
SYSCTL_FILE="${RLN_SYSCTL_FILE:-/etc/sysctl.d/99-rednetline-cascade.conf}"
UFW_BEFORE="${RLN_UFW_BEFORE:-/etc/ufw/before.rules}"
IPT_STATE="${RLN_IPT_STATE:-/etc/iptables/rules.v4}"

IPT="${RLN_IPTABLES:-iptables}"
IP_BIN="${RLN_IP:-ip}"
SYSCTL_BIN="${RLN_SYSCTL_BIN:-sysctl}"
NETFILTER_BIN="${RLN_NETFILTER_BIN:-netfilter-persistent}"

# Собственные цепочки: всё, что создаёт скрипт, живёт только в них.
CHAIN_PRE="RLN_PRE"     # nat PREROUTING   — DNAT
CHAIN_POST="RLN_POST"   # nat POSTROUTING  — MASQUERADE
CHAIN_FWD="RLN_FWD"     # filter FORWARD   — разрешение проброса
CHAIN_STAT="RLN_STAT"   # mangle FORWARD   — счётчики трафика (только счёт, ни на что не влияют)

# Маркеры управляемого блока в before.rules. Разбор идёт по префиксу, поэтому
# блоки nat и filter различаются суффиксом, а старый формат (без суффикса,
# остался от прежних версий) тоже находится и вычищается.
MARK_BEGIN="# BEGIN REDNETLINE CASCADE"
MARK_END="# END REDNETLINE CASCADE"
MARK_NAT_BEGIN="$MARK_BEGIN (nat)"
MARK_NAT_END="$MARK_END (nat)"
MARK_FILTER_BEGIN="$MARK_BEGIN (filter)"
MARK_FILTER_END="$MARK_END (filter)"
MARK_MANGLE_BEGIN="$MARK_BEGIN (mangle)"
MARK_MANGLE_END="$MARK_END (mangle)"

# --- ЦВЕТА (только для терминала) -------------------------------------------
if [ -t 1 ]; then
    C_RED=$'\033[0;31m'; C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[1;33m'
    C_CYAN=$'\033[0;36m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""; C_OFF=""
fi

# --- ВЫВОД И ЛОГИ -----------------------------------------------------------
# Данные (списки, статус) идут в stdout, служебные сообщения — в stderr.

log() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    printf '%s [%s] %s\n' "$(date '+%F %T')" "$$" "$*" >>"$LOG_FILE" 2>/dev/null || true
}

msg()  { printf '%s\n' "$*" >&2; }
ok()   { printf '%s[+] %s%s\n' "$C_GREEN"  "$*" "$C_OFF" >&2; log "OK: $*"; }
warn() { printf '%s[!] %s%s\n' "$C_YELLOW" "$*" "$C_OFF" >&2; log "WARN: $*"; }
err()  { printf '%s[x] %s%s\n' "$C_RED"    "$*" "$C_OFF" >&2; log "ERROR: $*"; }
die()  { err "$*"; exit 1; }

# printf выравнивает по байтам, поэтому на кириллице колонки разъезжаются.
# Считаем длину в символах (пропуская UTF-8 continuation-байты) и добиваем
# пробелами до нужной ширины.
padto() { # текст ширина
    local s="$1" w="$2" n=0 i c
    for ((i = 0; i < ${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [$'\200'-$'\277']) ;;
            *) n=$((n + 1)) ;;
        esac
    done
    n=$((w - n))
    if [ "$n" -lt 1 ]; then n=1; fi
    printf '%s%*s' "$s" "$n" ""
}

kv() { printf '%s%s\n' "$(padto "$1" 20)" "$2"; }

# Байты в человекочитаемый вид.
human() {
    local b="${1:-0}"
    case "$b" in ''|*[!0-9]*) b=0 ;; esac
    if   [ "$b" -ge 1073741824 ]; then printf '%d.%d ГБ' $((b / 1073741824)) $(((b % 1073741824) / 107374182))
    elif [ "$b" -ge 1048576 ];    then printf '%d.%d МБ' $((b / 1048576))    $(((b % 1048576) / 104858))
    elif [ "$b" -ge 1024 ];       then printf '%d.%d КБ' $((b / 1024))       $(((b % 1024) / 103))
    else printf '%d Б' "$b"; fi
}

# Сколько байт прошло через туннель: dir = fwd (к цели) или ret (обратно).
# Счётчики живут в mangle FORWARD — эта цепочка проходится КАЖДЫМ пакетом,
# в отличие от nat (только первый пакет потока) и filter (установившиеся
# пакеты перехватывает правило ufw раньше нашего).
stat_bytes() { # target out_port dir
    local target="$1" out_port="$2" dir="${3:-fwd}" field
    if [ "$dir" = ret ]; then field="spt:$out_port"; else field="dpt:$out_port"; fi
    $IPT -t mangle -L "$CHAIN_STAT" -v -x -n 2>/dev/null | awk -v t="$target" -v f="$field" '
        index($0, f) && index($0, t) { print $2; exit }'
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Требуются права root. Запустите: sudo $APP_BIN $*"
}

# --- ВАЛИДАЦИЯ --------------------------------------------------------------

# Порт: только цифры, 1..65535. Ведущие нули отбрасываются: iptables читает их
# как восьмеричные, из-за чего "0443" превратился бы в 291.
valid_port() {
    local p="${1:-}"
    case "$p" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#p}" -le 5 ] || return 1
    p=$((10#$p))
    [ "$p" -ge 1 ] && [ "$p" -le 65535 ]
}

norm_port() { printf '%d\n' "$((10#$1))"; }

valid_ip() {
    local ip="${1:-}" o
    case "$ip" in ''|*[!0-9.]*) return 1 ;; esac
    local IFS=.
    # shellcheck disable=SC2206
    local oct=($ip)
    [ "${#oct[@]}" -eq 4 ] || return 1
    for o in "${oct[@]}"; do
        case "$o" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#o}" -le 3 ] || return 1
        [ "$((10#$o))" -le 255 ] || return 1
    done
}

# --- СЕТЕВЫЕ ХЕЛПЕРЫ --------------------------------------------------------

wan_iface() {
    local out
    out="$($IP_BIN -4 route get 1.1.1.1 2>/dev/null || true)"
    [ -n "$out" ] || return 1
    awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }' <<<"$out"
}

# Является ли адрес адресом этого сервера (защита от петли).
is_local_ip() {
    local ip="$1" x
    while read -r x; do
        [ -n "$x" ] || continue
        if [ "$x" = "$ip" ]; then return 0; fi
    done < <($IP_BIN -o addr show 2>/dev/null | awk '{ print $4 }' | cut -d/ -f1 || true)
    return 1
}

# Порт, на котором слушает sshd: проброс его наружу отрезает доступ к серверу.
ssh_port() {
    local p=""
    if command -v sshd >/dev/null 2>&1; then
        p="$(sshd -T 2>/dev/null | awk '/^port /{ print $2; exit }' || true)"
    fi
    if [ -z "$p" ] && [ -r /etc/ssh/sshd_config ]; then
        p="$(awk 'tolower($1)=="port"{ print $2; exit }' /etc/ssh/sshd_config || true)"
    fi
    printf '%s\n' "${p:-22}"
}

# Занят ли порт локальным сервисом (тогда DNAT начнёт уводить и его трафик).
port_in_use() {
    local port="$1" out addr
    command -v ss >/dev/null 2>&1 || return 1
    out="$(ss -H -lntu 2>/dev/null || true)"
    [ -n "$out" ] || return 1
    while read -r _ _ _ _ addr _; do
        case "${addr:-}" in *":$port"|*".$port") return 0 ;; esac
    done <<<"$out"
    return 1
}

# --- СОСТОЯНИЕ (единственный источник правды о правилах) ---------------------
# Формат строки: proto in_port target out_port

state_init() {
    mkdir -p "$CONF_DIR"
    [ -f "$STATE_FILE" ] || : >"$STATE_FILE"
    chmod 600 "$STATE_FILE" 2>/dev/null || true
}

state_list() {
    [ -f "$STATE_FILE" ] || return 0
    grep -vE '^[[:space:]]*(#|$)' "$STATE_FILE" 2>/dev/null || true
}

# ВНИМАНИЕ: проверять наличие не через "| grep -q" — при set -o pipefail ранний
# выход grep даёт SIGPIPE писателю, пайплайн возвращает 141 и проверка ложно
# срабатывает как «правил нет».
state_has_rules() { [ -n "$(state_list)" ]; }

state_add() {
    local proto="$1" in_port="$2" target="$3" out_port="$4"
    state_init
    local tmp="$STATE_FILE.tmp.$$"
    {
        while read -r p i t o; do
            [ -n "${p:-}" ] || continue
            if [ "$p" = "$proto" ] && [ "$i" = "$in_port" ]; then continue; fi
            printf '%s %s %s %s\n' "$p" "$i" "$t" "$o"
        done < <(state_list) || true
        printf '%s %s %s %s\n' "$proto" "$in_port" "$target" "$out_port"
    } >"$tmp"
    mv -f "$tmp" "$STATE_FILE"
    chmod 600 "$STATE_FILE" 2>/dev/null || true
}

state_delete() {
    local proto="$1" in_port="$2"
    state_init
    local tmp="$STATE_FILE.tmp.$$" found=0
    {
        while read -r p i t o; do
            [ -n "${p:-}" ] || continue
            if [ "$p" = "$proto" ] && [ "$i" = "$in_port" ]; then found=1; continue; fi
            printf '%s %s %s %s\n' "$p" "$i" "$t" "$o"
        done < <(state_list) || true
    } >"$tmp"
    mv -f "$tmp" "$STATE_FILE"
    [ "$found" -eq 1 ]
}

state_clear() {
    state_init
    : >"$STATE_FILE"
}

# Найти правило по протоколу и входящему порту: печатает "target out_port".
state_get() {
    local proto="$1" in_port="$2"
    while read -r p i t o; do
        [ -n "${p:-}" ] || continue
        if [ "$p" = "$proto" ] && [ "$i" = "$in_port" ]; then
            printf '%s %s\n' "$t" "$o"
            return 0
        fi
    done < <(state_list) || true
    return 1
}

# --- СИСТЕМНЫЕ НАСТРОЙКИ ----------------------------------------------------

# ip_forward обязателен для проброса. BBR включаем, только если ядро его
# поддерживает — иначе честно сообщаем (в отличие от «включили и забыли»).
write_sysctl() {
    local want_bbr="$1" content
    content="# Управляется $APP_NAME. Ручные правки будут перезаписаны.
net.ipv4.ip_forward=1
"

    if [ "$want_bbr" = "yes" ]; then
        command -v modprobe >/dev/null 2>&1 && modprobe tcp_bbr 2>/dev/null || true
        if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            content+="net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
"
        else
            warn "Ядро не поддерживает BBR — параметры ускорения не записаны."
        fi
    fi

    printf '%s' "$content" >"$SYSCTL_FILE"
    if ! "$SYSCTL_BIN" -p "$SYSCTL_FILE" >/dev/null 2>&1; then
        warn "Не удалось применить $SYSCTL_FILE (проверьте вручную)."
    fi
}

check_ip_forward() {
    local v
    v="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
    [ "$v" = "1" ] || warn "ip_forward = $v — проброс работать не будет. Проверьте $SYSCTL_FILE."
}

# --- БЭКЕНД: ОПРЕДЕЛЕНИЕ ----------------------------------------------------

ufw_active() {
    command -v ufw >/dev/null 2>&1 || return 1
    local out
    out="$(ufw status 2>/dev/null || true)"
    case "$out" in
        *"Status: active"*) return 0 ;;
    esac
    return 1
}

ufw_block_present() {
    [ -f "$UFW_BEFORE" ] && grep -qF "$MARK_BEGIN" "$UFW_BEFORE" 2>/dev/null
}

chains_present() {
    command -v "$IPT" >/dev/null 2>&1 || return 1
    $IPT -t nat -n -L "$CHAIN_PRE" >/dev/null 2>&1
}

# Где правила лежат на самом деле — а не где мы предполагаем по статусу ufw.
backend_name() {
    if ufw_block_present; then
        printf 'ufw (before.rules)\n'
    elif chains_present; then
        printf 'iptables напрямую\n'
    elif ufw_active; then
        printf 'ufw активен, правила не применены\n'
    else
        printf 'не применены\n'
    fi
}

persistence_name() {
    if ufw_block_present; then
        printf 'ufw (before.rules)\n'
    elif command -v "$NETFILTER_BIN" >/dev/null 2>&1; then
        printf 'netfilter-persistent\n'
    else
        printf 'нет\n'
    fi
}

# --- БЭКЕНД 1: ПРЯМЫЕ ПРАВИЛА IPTABLES -------------------------------------

ensure_chain() { # table chain
    local table="$1" chain="$2"
    if ! $IPT -t "$table" -n -L "$chain" >/dev/null 2>&1; then
        $IPT -t "$table" -N "$chain" || die "Не удалось создать цепочку $chain в таблице $table"
    fi
}

ensure_jump() { # table chain target insert|append
    local table="$1" chain="$2" target="$3" mode="${4:-insert}"
    if ! $IPT -t "$table" -C "$chain" -j "$target" >/dev/null 2>&1; then
        if [ "$mode" = insert ]; then
            $IPT -t "$table" -I "$chain" 1 -j "$target" || die "Не удалось добавить переход в $target"
        else
            $IPT -t "$table" -A "$chain" -j "$target" || die "Не удалось добавить переход в $target"
        fi
    fi
}

# Полная пересборка собственных цепочек из state. Идемпотентно: повторный
# запуск даёт ровно тот же результат, дубликатов и «мёртвых» правил не бывает.
apply_direct() {
    local proto in_port target out_port wan

    command -v "$IPT" >/dev/null 2>&1 || die "$IPT не найден. Установите пакет iptables."

    ensure_chain nat "$CHAIN_PRE"
    ensure_chain nat "$CHAIN_POST"
    ensure_jump  nat PREROUTING  "$CHAIN_PRE"  insert
    ensure_jump  nat POSTROUTING "$CHAIN_POST" append
    $IPT -t nat -F "$CHAIN_PRE"
    $IPT -t nat -F "$CHAIN_POST"

    # Разрешение проброса. Стоит первым в FORWARD, поэтому чужие правила
    # (ufw, docker) продолжают работать как обычно.
    ensure_chain filter "$CHAIN_FWD"
    ensure_jump  filter FORWARD "$CHAIN_FWD" insert
    $IPT -F "$CHAIN_FWD"

    # Счётчики трафика: mangle проходится каждым пакетом, поэтому цифры точные
    ensure_chain mangle "$CHAIN_STAT"
    ensure_jump  mangle FORWARD "$CHAIN_STAT" append
    $IPT -t mangle -F "$CHAIN_STAT"

    # Наполнение из state. Те же правила, что и в render_*_block: правки в
    # конструкции правила нужно вносить в обоих местах.
    while read -r proto in_port target out_port; do
        [ -n "${proto:-}" ] || continue
        $IPT -t nat -A "$CHAIN_PRE" -p "$proto" --dport "$in_port" \
            -j DNAT --to-destination "$target:$out_port" \
            || die "Не удалось добавить DNAT $proto/$in_port -> $target:$out_port"
        $IPT -A "$CHAIN_FWD" -p "$proto" -d "$target" --dport "$out_port" \
            -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT \
            || die "Не удалось добавить правило FORWARD"
        $IPT -A "$CHAIN_FWD" -p "$proto" -s "$target" --sport "$out_port" \
            -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
            || die "Не удалось добавить правило FORWARD"
        $IPT -t mangle -A "$CHAIN_STAT" -p "$proto" -d "$target" --dport "$out_port" -j RETURN
        $IPT -t mangle -A "$CHAIN_STAT" -p "$proto" -s "$target" --sport "$out_port" -j RETURN
    done < <(state_list)

    if state_has_rules; then
        wan="$(wan_iface || true)"
        if [ -n "$wan" ]; then
            $IPT -t nat -A "$CHAIN_POST" -o "$wan" -m conntrack --ctstate DNAT \
                -j MASQUERADE || die "Не удалось добавить MASQUERADE"
        else
            warn "Не удалось определить внешний интерфейс — MASQUERADE не добавлен."
        fi
    fi

    netfilter_save
}

# Снять все наши цепочки и переходы. Переходы снимаем в цикле, а не по одному:
# ufw не сбрасывает таблицы, поэтому каждый его reload дописывает из
# before.rules ещё одну копию — так повторный apply сходится к одному переходу.
remove_chains() {
    command -v "$IPT" >/dev/null 2>&1 || return 0
    while $IPT -t nat -D PREROUTING -j "$CHAIN_PRE" 2>/dev/null; do :; done
    while $IPT -t nat -D POSTROUTING -j "$CHAIN_POST" 2>/dev/null; do :; done
    while $IPT -D FORWARD -j "$CHAIN_FWD" 2>/dev/null; do :; done
    while $IPT -t mangle -D FORWARD -j "$CHAIN_STAT" 2>/dev/null; do :; done
    $IPT -t nat -F "$CHAIN_PRE"  2>/dev/null || true
    $IPT -t nat -F "$CHAIN_POST" 2>/dev/null || true
    $IPT -F "$CHAIN_FWD" 2>/dev/null || true
    $IPT -t nat -X "$CHAIN_PRE"  2>/dev/null || true
    $IPT -t nat -X "$CHAIN_POST" 2>/dev/null || true
    $IPT -X "$CHAIN_FWD" 2>/dev/null || true
    $IPT -t mangle -F "$CHAIN_STAT" 2>/dev/null || true
    $IPT -t mangle -X "$CHAIN_STAT" 2>/dev/null || true
    return 0
}

# Персистентность прямого пути обеспечивает netfilter-persistent. Если его нет —
# предлагаем установить (в неинтерактивном режиме только с --install-deps).
ensure_persistence() {
    if command -v "$NETFILTER_BIN" >/dev/null 2>&1; then return 0; fi

    if [ "${RLN_INSTALL_DEPS:-0}" != "1" ]; then
        if [ -t 0 ]; then
            printf '%s[?] netfilter-persistent не найден — правила не переживут перезагрузку. Установить iptables-persistent? [Y/n]: %s' "$C_YELLOW" "$C_OFF" >&2
            local a=""
            read -r a || a="n"
            case "$a" in
                n|N|no|NO|нет|Нет|НЕТ) warn "Установка пропущена — правила не сохранятся после перезагрузки."; return 0 ;;
            esac
            export RLN_INSTALL_DEPS=1
        else
            warn "netfilter-persistent не найден: правила не переживут перезагрузку."
            warn "Установите пакет или запустите с флагом --install-deps."
            return 0
        fi
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        warn "apt-get не найден — установите пакет iptables-persistent вручную."
        return 0
    fi

    msg "Устанавливаю iptables-persistent..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent >/dev/null 2>&1 \
       && command -v "$NETFILTER_BIN" >/dev/null 2>&1; then
        ok "netfilter-persistent установлен."
    else
        warn "Не удалось установить iptables-persistent — правила не сохранятся после перезагрузки."
    fi
    return 0
}

netfilter_save() {
    if command -v "$NETFILTER_BIN" >/dev/null 2>&1; then
        if "$NETFILTER_BIN" save >/dev/null 2>&1; then
            log "netfilter-persistent save: ok"
        else
            warn "netfilter-persistent save завершился с ошибкой — правила могут не пережить перезагрузку."
        fi
    else
        warn "netfilter-persistent не найден: правила не сохранятся после перезагрузки."
    fi
}

# --- БЭКЕНД 2: UFW ----------------------------------------------------------
# На хосте с активным ufw правила обязаны лежать в before.rules: их загружает
# сам ufw при старте, поэтому они переживают перезагрузку и не появляется
# второй загрузчик (netfilter-persistent), который воевал бы с ufw.
#
# ufw вставляет свои переходы в начало FORWARD, вытесняя наш вниз. Это не
# мешает: политика цепочки применяется, только если ни одно правило не дало
# вердикт, а наши ACCEPT-правила срабатывают раньше политики. Поэтому менять
# DEFAULT_FORWARD_POLICY на ACCEPT (как делал оригинальный скрипт) не нужно.

render_nat_block() {
    local wan
    wan="$(wan_iface || true)"

    printf '%s\n' "$MARK_NAT_BEGIN"
    printf '*nat\n'
    printf ':PREROUTING ACCEPT [0:0]\n'
    printf ':POSTROUTING ACCEPT [0:0]\n'
    printf ':%s - [0:0]\n' "$CHAIN_PRE"
    printf ':%s - [0:0]\n' "$CHAIN_POST"
    printf -- '-A PREROUTING -j %s\n' "$CHAIN_PRE"
    printf -- '-A POSTROUTING -j %s\n' "$CHAIN_POST"
    while read -r proto in_port target out_port; do
        [ -n "${proto:-}" ] || continue
        printf -- '-A %s -p %s --dport %s -j DNAT --to-destination %s:%s\n' \
            "$CHAIN_PRE" "$proto" "$in_port" "$target" "$out_port"
    done < <(state_list)
    if [ -n "$wan" ]; then
        printf -- '-A %s -o %s -m conntrack --ctstate DNAT -j MASQUERADE\n' "$CHAIN_POST" "$wan"
    fi
    printf 'COMMIT\n'
    printf '%s\n' "$MARK_NAT_END"
}

render_filter_block() {
    printf '%s\n' "$MARK_FILTER_BEGIN"
    printf ':%s - [0:0]\n' "$CHAIN_FWD"
    printf -- '-A FORWARD -j %s\n' "$CHAIN_FWD"
    while read -r proto in_port target out_port; do
        [ -n "${proto:-}" ] || continue
        printf -- '-A %s -p %s -d %s --dport %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n' \
            "$CHAIN_FWD" "$proto" "$target" "$out_port"
        printf -- '-A %s -p %s -s %s --sport %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n' \
            "$CHAIN_FWD" "$proto" "$target" "$out_port"
    done < <(state_list)
    printf '%s\n' "$MARK_FILTER_END"
}

# Счётные правила. Все с RETURN — на прохождение пакетов не влияют.
render_mangle_block() {
    printf '%s\n' "$MARK_MANGLE_BEGIN"
    printf '*mangle\n'
    printf ':%s - [0:0]\n' "$CHAIN_STAT"
    printf -- '-A FORWARD -j %s\n' "$CHAIN_STAT"
    while read -r proto in_port target out_port; do
        [ -n "${proto:-}" ] || continue
        printf -- '-A %s -p %s -d %s --dport %s -j RETURN\n' "$CHAIN_STAT" "$proto" "$target" "$out_port"
        printf -- '-A %s -p %s -s %s --sport %s -j RETURN\n' "$CHAIN_STAT" "$proto" "$target" "$out_port"
    done < <(state_list)
    printf 'COMMIT\n'
    printf '%s\n' "$MARK_MANGLE_END"
}

# Убирает наши блоки из текста (идемпотентно).
strip_ufw_block() {
    local file="$1"
    [ -f "$file" ] || return 0
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
        index($0, b) == 1 { skip = 1; next }
        index($0, e) == 1 { skip = 0; next }
        !skip
    ' "$file"
}

# Есть ли в тексте секция таблицы (*nat / *filter). Строчно и без пайпа в grep:
# при set -o pipefail ранний выход grep даёт SIGPIPE и ложный результат.
content_has_table() { # текст имя_таблицы
    local content="$1" t="$2" line
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        case "$line" in \*"$t"*) return 0 ;; esac
    done <<<"$content"
    return 1
}

# Новый файл проверяем через iptables-restore --test и только потом ставим.
install_ufw_file() {
    local file="$1" tmp="$2"
    if command -v iptables-restore >/dev/null 2>&1; then
        if ! iptables-restore --test <"$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"
            err "Новый $file не проходит проверку (iptables-restore --test) — файл не изменён."
            return 1
        fi
    else
        warn "iptables-restore не найден — проверка файла пропущена."
    fi

    [ -f "$file.rln.bak" ] || cp -p "$file" "$file.rln.bak" 2>/dev/null || true
    chmod --reference="$file" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$file"
    log "Обновлён $file"
}

apply_ufw() {
    local file="$UFW_BEFORE" nat filter mangle ins tmp stripped
    [ -f "$file" ] || { err "Не найден $file — ufw не настроен?"; return 1; }

    if state_has_rules; then
        nat="$(render_nat_block)"
        filter="$(render_filter_block)"
        mangle="$(render_mangle_block)"

        # Наш прежний блок снимаем ДО поиска чужой секции *nat: иначе на
        # повторном применении мы нашли бы собственную и отказались работать.
        stripped="$(strip_ufw_block "$file" || true)"

        if content_has_table "$stripped" nat; then
            err "$file содержит чужую секцию *nat — объедините правила вручную"
            err "(iptables-restore не принимает две секции *nat) или отключите ufw."
            return 1
        fi
        if ! content_has_table "$stripped" filter; then
            err "$file не содержит секции *filter — некуда вставить правила FORWARD."
            return 1
        fi
        # Чужая секция *mangle — не повод ломать проброс: просто не будет счётчиков.
        if content_has_table "$stripped" mangle; then
            warn "$file содержит чужую секцию *mangle — учёт трафика пропущен."
            mangle=""
        fi

        # nat-блок — в начало файла, filter-блок — сразу после «*filter».
        tmp="$file.rln.$$"
        {
            [ -n "$mangle" ] && printf '%s\n' "$mangle"
            printf '%s\n' "$nat"
            ins=0
            printf '%s\n' "$stripped" | while IFS= read -r line; do
                printf '%s\n' "$line"
                case "$line" in
                    \*filter*)
                        if [ "$ins" -eq 0 ]; then printf '%s\n' "$filter"; ins=1; fi
                        ;;
                esac
            done
        } >"$tmp" || true
        install_ufw_file "$file" "$tmp" || return 1
    else
        # Правил нет — убираем блоки, если они остались от прошлого запуска.
        if ufw_block_present; then
            tmp="$file.rln.$$"
            strip_ufw_block "$file" >"$tmp" || true
            install_ufw_file "$file" "$tmp" || return 1
        fi
    fi

    # Файл записан и проверен — убираем цепочки от прежнего прямого применения,
    # иначе в ядре останутся два набора правил и старое (оно идёт первым)
    # перебьёт новую цель.
    remove_chains

    if [ -f "$IPT_STATE" ] && grep -q 'RLN_' "$IPT_STATE" 2>/dev/null; then
        warn "Найден $IPT_STATE с нашими правилами от прежнего прямого применения."
        warn "При активном ufw его лучше удалить, иначе после перезагрузки два"
        warn "загрузчика перезапишут друг друга: rm -f $IPT_STATE"
    fi

    if ! ufw reload >/dev/null 2>&1; then
        warn "ufw reload завершился с ошибкой — проверьте 'ufw status' вручную."
    fi
}

# --- ПРИМЕНЕНИЕ И ПРОВЕРКА --------------------------------------------------

apply_all() {
    local bbr="${1:-yes}"
    state_init

    if ufw_active && [ "${RLN_DIRECT:-0}" != "1" ]; then
        apply_ufw || return 1
    else
        if ufw_active; then
            warn "Режим --direct при активном ufw: правила лягут прямо в iptables,"
            warn "а перезагружать их будет netfilter-persistent — у него с ufw два"
            warn "независимых загрузчика, при перезагрузке возможен конфликт."
        fi
        ensure_persistence
        apply_direct
    fi

    write_sysctl "$bbr"
    check_ip_forward

    if ! verify_applied; then
        err "Часть правил отсутствует в ядре после применения."
        return 1
    fi
    return 0
}

# Есть ли правило в живых правилах ядра (построчно, без пайпа в grep).
verify_one() {
    local proto="$1" in_port="$2" out line
    command -v "$IPT" >/dev/null 2>&1 || return 1
    out="$($IPT -t nat -S "$CHAIN_PRE" 2>/dev/null || true)"
    [ -n "$out" ] || return 1
    while IFS= read -r line; do
        case "$line" in
            *" -p $proto "*"--dport $in_port "*) return 0 ;;
        esac
    done <<<"$out"
    return 1
}

verify_applied() {
    local rc=0 proto in_port target out_port
    while read -r proto in_port target out_port; do
        [ -n "${proto:-}" ] || continue
        if ! verify_one "$proto" "$in_port"; then
            err "Правило $proto/$in_port -> $target:$out_port не найдено в ядре."
            rc=1
        fi
    done < <(state_list) || true
    return "$rc"
}

# --- КОМАНДЫ ----------------------------------------------------------------

cmd_add() {
    local proto="${1:-}" in_port="${2:-}" target="${3:-}" out_port="${4:-}"
    local force="${5:-0}" old sp

    [ -n "$proto" ] && [ -n "$in_port" ] && [ -n "$target" ] || {
        err "Использование: $APP_BIN add <tcp|udp> <вход.порт> <IP назначения> [вых.порт] [--force]"
        return 1
    }
    case "$proto" in tcp|udp) ;; *) err "Протокол должен быть tcp или udp (получено: $proto)"; return 1 ;; esac
    valid_port "$in_port" || { err "Некорректный входящий порт: $in_port"; return 1; }
    valid_ip "$target"    || { err "Некорректный IP назначения: $target"; return 1; }
    [ -n "$out_port" ] || out_port="$in_port"
    valid_port "$out_port" || { err "Некорректный исходящий порт: $out_port"; return 1; }

    in_port="$(norm_port "$in_port")"
    out_port="$(norm_port "$out_port")"

    if is_local_ip "$target"; then
        err "IP назначения совпадает с адресом этого сервера — получится петля."
        return 1
    fi

    sp="$(ssh_port)"
    if [ "$in_port" = "$sp" ] && [ "$force" != "1" ]; then
        err "Порт $in_port — это порт SSH этого сервера."
        err "Проброс уведёт подключения к нему на $target — вы потеряете доступ к VPS."
        err "Если это действительно нужно, повторите с флагом --force."
        return 1
    fi

    if port_in_use "$in_port"; then
        warn "Порт $in_port занят локальным сервисом — DNAT начнёт уводить и его трафик."
    fi

    if old="$(state_get "$proto" "$in_port")"; then
        warn "Правило $proto/$in_port уже было ($old) — заменяю на $target:$out_port."
    fi

    state_add "$proto" "$in_port" "$target" "$out_port"
    log "add: $proto $in_port -> $target:$out_port"

    apply_all "${RLN_BBR:-yes}" || { err "Правило сохранено, но применить не удалось."; return 1; }
    ok "$proto: $in_port -> $target:$out_port"
}

cmd_delete() {
    local proto="${1:-}" in_port="${2:-}"
    [ -n "$proto" ] && [ -n "$in_port" ] || { err "Использование: $APP_BIN delete <tcp|udp> <вход.порт>"; return 1; }
    valid_port "$in_port" || { err "Некорректный порт: $in_port"; return 1; }
    in_port="$(norm_port "$in_port")"

    if ! state_delete "$proto" "$in_port"; then
        err "Правило $proto/$in_port не найдено."
        return 1
    fi
    log "delete: $proto $in_port"
    apply_all "${RLN_BBR:-yes}" || { err "Правило удалено из конфигурации, но применить не удалось."; return 1; }
    ok "Правило $proto/$in_port удалено."
}

cmd_flush() {
    local assume_yes="${1:-0}" a=""
    if [ "$assume_yes" != "1" ]; then
        printf '%sУдалить все правила %s? [y/N]: %s' "$C_YELLOW" "$APP_NAME" "$C_OFF" >&2
        read -r a || a=""
        case "$a" in y|Y|yes|YES|да|Да) ;; *) msg "Отменено."; return 0 ;; esac
    fi
    state_clear
    log "flush: все правила удалены"
    apply_all "${RLN_BBR:-yes}" || { err "Не удалось применить пустую конфигурацию."; return 1; }
    ok "Все правила $APP_NAME удалены. Остальные правила системы не тронуты."
}

cmd_list() {
    local count=0 proto in_port target out_port mark
    printf '%s%s %s %s %s %s %s%s\n' "$C_BOLD" "$(padto "ПРОТО" 6)" "$(padto "ВХОД" 7)" \
        "$(padto "ЦЕЛЬ" 16)" "$(padto "ВЫХОД" 7)" "$(padto "ТУДА" 10)" "ОБРАТНО" "$C_OFF"
    while read -r proto in_port target out_port; do
        [ -n "${proto:-}" ] || continue
        count=$((count + 1))
        mark=""
        verify_one "$proto" "$in_port" || mark=" ${C_RED}(не применено)${C_OFF}"
        printf '%s %s %s %s %s %s%s\n' "$(padto "$proto" 6)" "$(padto "$in_port" 7)" \
            "$(padto "$target" 16)" "$(padto "$out_port" 7)" \
            "$(padto "$(human "$(stat_bytes "$target" "$out_port" fwd)")" 10)" \
            "$(human "$(stat_bytes "$target" "$out_port" ret)")" "$mark"
    done < <(state_list) || true
    [ "$count" -gt 0 ] || printf '%s\n' "Правил нет."
    return 0
}

cmd_status() {
    local fwd bbr ufw_state rules live jumps
    fwd="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')"
    bbr="$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || echo '?')"
    ufw_state="не активен"
    if ufw_active; then ufw_state="АКТИВЕН"; fi
    rules="$(state_list | grep -c . || true)"
    live="$($IPT -t nat -S "$CHAIN_PRE" 2>/dev/null | grep -c 'DNAT' || true)"
    rules="${rules:-0}"; live="${live:-0}"

    printf '%s%s %s%s\n' "$C_BOLD" "$APP_NAME" "$APP_VERSION" "$C_OFF"
    kv "Правила:"         "$(backend_name)"
    kv "ufw:"             "$ufw_state"
    kv "ip_forward:"      "$fwd"
    kv "congestion:"      "$bbr"
    kv "Правил:"          "$rules"
    kv "Живых DNAT:"      "$live"
    kv "Персистентность:" "$(persistence_name)"
    kv "Конфиг:"          "$STATE_FILE"
    kv "Лог:"             "$LOG_FILE"

    if [ "$fwd" != "1" ]; then
        warn "ip_forward выключен — проброс не работает."
    fi
    if [ "$rules" -gt 0 ] && [ "$live" != "$rules" ]; then
        warn "Правил в конфиге ($rules), живых DNAT ($live). Выполните: $APP_BIN apply"
    fi
    # ufw reload дописывает копию нашего перехода в FORWARD (таблицы не
    # сбрасываются). На работу не влияет, лечится повторным apply.
    jumps="$($IPT -S FORWARD 2>/dev/null | grep -c -- "FORWARD -j $CHAIN_FWD" || true)"
    if [ "${jumps:-0}" -gt 1 ]; then
        warn "Переход в $CHAIN_FWD продублирован ($jumps копий после ufw reload)."
        warn "Выполните: $APP_BIN apply — лишние копии будут убраны."
    fi
    return 0
}

self_install() {
    local self
    self="$(readlink -f "$0" 2>/dev/null || printf '%s\n' "$0")"

    case "$(basename "$self")" in
        bash|sh|dash|-bash|ash)
            warn "Скрипт запущен через pipe — самокопирование пропущено."
            warn "Скачайте файл и запустите: chmod +x $0 && ./$(basename "$0")"
            return 0 ;;
    esac
    case "$self" in
        /dev/fd/*|/dev/stdin|/proc/*/fd/*)
            warn "Скрипт запущен через подстановку файла — самокопирование пропущено."
            return 0 ;;
    esac

    if [ "$self" = "$APP_BIN" ]; then return 0; fi
    if [ ! -r "$self" ]; then return 0; fi

    if install -m 0755 "$self" "$APP_BIN" 2>/dev/null; then
        ok "Установлено: $APP_BIN (запуск командой 'rednetline')"
    else
        warn "Не удалось скопировать скрипт в $APP_BIN."
    fi
}

cmd_uninstall() {
    local assume_yes="${1:-0}" a=""
    if [ "$assume_yes" != "1" ]; then
        printf '%sУдалить %s (правила, цепочки, конфиг, %s)? [y/N]: %s' \
            "$C_YELLOW" "$APP_NAME" "$APP_BIN" "$C_OFF" >&2
        read -r a || a=""
        case "$a" in y|Y|yes|YES|да|Да) ;; *) msg "Отменено."; return 0 ;; esac
    fi

    state_clear
    # Пустое состояние: apply_ufw затрёт наш блок в before.rules и перезагрузит ufw.
    if ufw_block_present; then apply_ufw || true; fi
    remove_chains

    # На хосте с ufw снапшот rules.v4 создавать нельзя — он будет воевать с ufw
    # при перезагрузке (два независимых загрузчика в одни и те же таблицы).
    if ! ufw_active; then netfilter_save; fi

    rm -f "$STATE_FILE" "$SYSCTL_FILE"
    rmdir "$CONF_DIR" 2>/dev/null || true
    rm -f "$APP_BIN"
    ok "$APP_NAME удалён."
    msg "Правила других сервисов (ufw, docker, fail2ban) не затронуты."
}

cmd_help() {
    cat <<EOF
$APP_NAME $APP_VERSION — каскадная переадресация трафика на VPS.

Схема: клиент -> этот VPS (DNAT) -> зарубежный сервер.

Команды:
  add <tcp|udp> <вход.порт> <IP назначения> [вых.порт]
                              Добавить или заменить правило
  delete <tcp|udp> <вход.порт>
                              Удалить правило
  list                        Показать правила
  status                      Диагностика (форвардинг, BBR, ufw, цепочки)
  apply                       Применить конфиг к ядру
  flush [--yes]               Удалить все правила $APP_NAME
  install                     Скопировать скрипт в $APP_BIN
  uninstall [--yes]           Полное удаление (правила, конфиг, бинарник)
  menu                        Интерактивное меню (по умолчанию)
  help | version

Примеры:
  $(basename "$APP_BIN") add udp 51820 203.0.113.10
  $(basename "$APP_BIN") add tcp 443 203.0.113.10 443
  $(basename "$APP_BIN") add tcp 2222 203.0.113.10 22      # проброс SSH
  $(basename "$APP_BIN") delete tcp 443

Как настроить клиент:
  1. Добавьте правило на этом VPS (протокол, входящий порт, IP и порт назначения).
  2. В клиенте (AmneziaWG, VLESS, MTProto) замените адрес зарубежного сервера
     на IP этого VPS. Порт — только если входящий и исходящий порты различаются.

Флаги:
  --force         разрешить проброс SSH-порта этого сервера
  --direct        писать правила прямо в iptables даже при активном ufw
                  (по умолчанию при ufw используется before.rules)
  --install-deps  без вопросов установить iptables-persistent, если его нет
  --no-bbr        не включать BBR
EOF
}

# --- ИНТЕРАКТИВНОЕ МЕНЮ -----------------------------------------------------

ask() { # приглашение -> stdout
    local prompt="$1" out=""
    printf '%s' "$prompt" >&2
    read -r out || return 1
    printf '%s\n' "$out"
}

menu_add() { # proto name
    local proto="$1" name="$2" in_port target out_port
    printf '\n%s--- %s (%s) ---%s\n' "$C_CYAN" "$name" "$proto" "$C_OFF" >&2

    target="$(ask "IP назначения (зарубежный сервер): ")" || return 0
    valid_ip "$target" || { err "Некорректный IP: $target"; return 0; }

    in_port="$(ask "Входящий порт (на этом VPS): ")" || return 0
    valid_port "$in_port" || { err "Некорректный порт: $in_port"; return 0; }

    printf 'Исходящий порт [Enter = %s]: ' "$in_port" >&2
    out_port=""
    read -r out_port || return 0
    [ -n "$out_port" ] || out_port="$in_port"

    cmd_add "$proto" "$in_port" "$target" "$out_port" || true
    printf '\n' >&2
    read -r -p "Нажмите Enter..." _ || true
}

menu_delete() {
    local -a list=()
    local proto in_port target out_port line i choice

    while read -r proto in_port target out_port; do
        [ -n "${proto:-}" ] || continue
        list+=("$proto $in_port $target $out_port")
    done < <(state_list) || true

    if [ "${#list[@]}" -eq 0 ]; then
        msg "Правил нет."
        read -r -p "Нажмите Enter..." _ || true
        return 0
    fi

    printf '\n%s--- Удаление правила ---%s\n' "$C_CYAN" "$C_OFF" >&2
    i=1
    for line in "${list[@]}"; do
        read -r proto in_port target out_port <<<"$line"
        printf '%s[%s]%s %s/%s -> %s:%s\n' "$C_YELLOW" "$i" "$C_OFF" "$proto" "$in_port" "$target" "$out_port" >&2
        i=$((i + 1))
    done

    choice="$(ask "Номер правила (0 — отмена): ")" || return 0
    case "$choice" in
        0|"") return 0 ;;
        *[!0-9]*) err "Нужен номер."; return 0 ;;
    esac
    [ "$choice" -ge 1 ] && [ "$choice" -le "${#list[@]}" ] || { err "Нет такого номера."; return 0; }

    read -r proto in_port target out_port <<<"${list[$((choice - 1))]}"
    cmd_delete "$proto" "$in_port" || true
    read -r -p "Нажмите Enter..." _ || true
}

show_menu() {
    local choice p
    while true; do
        clear
        printf '%s%s %s%s\n' "$C_BOLD" "$APP_NAME" "$APP_VERSION" "$C_OFF"
        printf 'Каскадная переадресация (DNAT) для VPS\n'
        printf -- '------------------------------------------------------\n'
        printf '1) Добавить правило %sAmneziaWG / WireGuard%s (UDP)\n' "$C_CYAN" "$C_OFF"
        printf '2) Добавить правило %sVLESS / XRay%s (TCP)\n' "$C_CYAN" "$C_OFF"
        printf '3) Добавить правило %sMTProto%s (TCP)\n' "$C_CYAN" "$C_OFF"
        printf '4) Добавить правило %sвручную%s (tcp/udp, разные порты)\n' "$C_CYAN" "$C_OFF"
        printf -- '------------------------------------------------------\n'
        printf '5) Показать правила\n'
        printf '6) Удалить правило\n'
        printf '7) Удалить все правила %s\n' "$APP_NAME"
        printf '8) Диагностика\n'
        printf '9) Справка\n'
        printf '0) Выход\n'
        printf -- '------------------------------------------------------\n'

        choice="$(ask "Ваш выбор: ")" || { printf '\n' >&2; return 0; }
        case "$choice" in
            1) menu_add "udp" "AmneziaWG / WireGuard" ;;
            2) menu_add "tcp" "VLESS / XRay" ;;
            3) menu_add "tcp" "MTProto" ;;
            4)
                p="$(ask 'Протокол (tcp/udp): ')" || continue
                case "$p" in tcp|udp) ;; *) err "Нужно tcp или udp."; continue ;; esac
                menu_add "$p" "Правило" ;;
            5) cmd_list; printf '\n' >&2; read -r -p "Нажмите Enter..." _ || true ;;
            6) menu_delete ;;
            7) cmd_flush 0 || true; read -r -p "Нажмите Enter..." _ || true ;;
            8) cmd_status; printf '\n' >&2; read -r -p "Нажмите Enter..." _ || true ;;
            9) cmd_help; printf '\n' >&2; read -r -p "Нажмите Enter..." _ || true ;;
            0) return 0 ;;
            *) ;;
        esac
    done
}

# --- РАЗБОР АРГУМЕНТОВ И ЗАПУСК ---------------------------------------------

main() {
    local cmd="${1:-menu}"
    shift || true

    local force=0 assume_yes=0 a
    local -a args=()
    for a in "$@"; do
        case "$a" in
            --force)        force=1 ;;
            --yes|-y)       assume_yes=1 ;;
            --direct)       export RLN_DIRECT=1 ;;
            --install-deps) export RLN_INSTALL_DEPS=1 ;;
            --no-bbr)       export RLN_BBR=no ;;
            *)              args+=("$a") ;;
        esac
    done

    case "$cmd" in
        help|-h|--help)    cmd_help; return 0 ;;
        version|-v|--version) printf '%s %s\n' "$APP_NAME" "$APP_VERSION"; return 0 ;;
        add)      require_root "add"; cmd_add "${args[0]:-}" "${args[1]:-}" "${args[2]:-}" "${args[3]:-}" "$force" ;;
        delete|del|remove) require_root "delete"; cmd_delete "${args[0]:-}" "${args[1]:-}" ;;
        list|ls)  require_root "list"; cmd_list ;;
        status)   cmd_status ;;
        apply)
            require_root "apply"
            if apply_all "${RLN_BBR:-yes}"; then ok "Конфигурация применена."; else return 1; fi ;;
        flush)     require_root "flush"; cmd_flush "$assume_yes" ;;
        install)   require_root "install"; self_install ;;
        uninstall) require_root "uninstall"; cmd_uninstall "$assume_yes" ;;
        menu)      require_root "menu"; self_install; show_menu ;;
        *) err "Неизвестная команда: $cmd"; msg "Справка: $APP_BIN help"; return 1 ;;
    esac
}

main "$@"
