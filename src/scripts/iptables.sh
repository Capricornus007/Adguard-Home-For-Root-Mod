#!/system/bin/sh
# 攔截層：v4 DNS 劫持進 AGH、v6 DNS 明確拒絕（REJECT 而非 DROP——drop 讓解析器
# 等滿超時才回退 v4，表現為「連了網沒 Internet」的隨機卡頓；reject 立即回退，
# twoone-3 issue #71 的教訓）、DoT(853) 阻斷（防系統私下繞過 AGH 走加密 DNS）。
# 免死金牌只給 AGH 進程自己（root:net_raw）——它的上游查詢不能被劫持回自己。
# 帶 5 秒守護循環：進程掉了重啟、規則被刷掉了重建（VPN 啟停會沖掉 nat 規則）。
AGH_DIR="/data/adb/agh"
. "$AGH_DIR/scripts/config.prop" 2>/dev/null || {
    redir_port=5591
    adg_user=root
    adg_group=net_raw
}
MAIN_LOG="$AGH_DIR/agh.log"
IPT="iptables -w 5"
IP6T="ip6tables -w 5"

log() { echo "$(date '+%F %T') [iptables] $1" >> "$MAIN_LOG"; }

# 防止重複啟動
[ "$(pgrep -f "$0" | wc -l)" -gt 1 ] && exit

setup_rules() {
    # AGH 掉進程則先拉起
    pgrep -x AdGuardHome >/dev/null || {
        log "AdGuardHome 進程丟失，重啟..."
        export SSL_CERT_DIR="/system/etc/security/cacerts/"
        "$AGH_DIR/bin/AdGuardHome" --no-check-update &
    }

    # ---- v4：nat OUTPUT 劫持 53 → AGH ----
    $IPT -t nat -L ADGUARD >/dev/null 2>&1 || {
        $IPT -t nat -N ADGUARD
        $IPT -t nat -I OUTPUT -j ADGUARD
    }
    $IPT -t nat -F ADGUARD
    # AGH 自身豁免（uid+gid 同時匹配，只放 AGH 進程）
    $IPT -t nat -A ADGUARD -m owner --uid-owner "$adg_user" --gid-owner "$adg_group" -j RETURN
    # 額外目的地址豁免（config.prop 的 ignore_dest_list，空格分隔）
    [ -n "$ignore_dest_list" ] && for d in $ignore_dest_list; do
        $IPT -t nat -A ADGUARD -d "$d" -j RETURN 2>/dev/null
    done
    $IPT -t nat -A ADGUARD -p udp --dport 53 -j REDIRECT --to-ports "$redir_port"
    $IPT -t nat -A ADGUARD -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port"

    # ---- DoT 阻斷（v4+v6, 853）----
    $IP6T -C OUTPUT -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        $IP6T -I OUTPUT -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        $IP6T -I OUTPUT -p tcp --dport 853 -j DROP
    $IP6T -C OUTPUT -p udp --dport 853 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
        $IP6T -I OUTPUT -p udp --dport 853 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
        $IP6T -I OUTPUT -p udp --dport 853 -j DROP
    $IPT -C OUTPUT -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        $IPT -I OUTPUT -p tcp --dport 853 -j REJECT --reject-with tcp-reset
    $IPT -C OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null || \
        $IPT -I OUTPUT -p udp --dport 853 -j REJECT

    # ---- v6 DNS：REJECT（優先）而非 DROP ----
    $IP6T -C OUTPUT -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
        $IP6T -I OUTPUT -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
        $IP6T -I OUTPUT -p udp --dport 53 -j DROP
    $IP6T -C OUTPUT -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        $IP6T -I OUTPUT -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        $IP6T -I OUTPUT -p tcp --dport 53 -j DROP

    log "規則已應用（v4 劫持:$redir_port / v6 REJECT / DoT 阻斷）"
}

rules_ok() {
    $IPT -t nat -C ADGUARD -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null && \
    $IPT -t nat -C ADGUARD -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null && \
    $IP6T -C OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null && \
    $IP6T -C OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null
}

# ---- 守護循環 ----
while true; do
    # config.prop 可能在運行中被改（重載端口等）
    [ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"
    if ! pgrep -x AdGuardHome >/dev/null || ! rules_ok; then
        setup_rules
        # 規則剛建好後刷新網路讓解析器立即走新路徑（飛行模式開關一次）
        for s in 1 0; do
            settings put global airplane_mode_on $s
            am broadcast -a android.intent.action.AIRPLANE_MODE
        done
    fi
    sleep 5
done &
