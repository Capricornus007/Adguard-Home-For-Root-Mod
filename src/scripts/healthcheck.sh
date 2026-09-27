#!/system/bin/sh
# AdGuardHome 上游健康探測＋自動重啟。
#
# 為什麼要有這支腳本（2026-09-27 真實故障）：
# AGH「進程活著」不等於「能用」。當時活配置裡三條 DoH 上游全部因線路改變而不可達
# （8.8.8.8:443 逾時、1.1.1.1:443 被拒、dns.sb 被 bootstrap 解成 127.0.0.1），
# 而故障形態是**靜默**的：命中黑名單的查詢仍然 0.07ms 秒回 0.0.0.0（看起來完全正常），
# 但凡需要走上游的查詢要掛滿 upstream_timeout(10s) 才失敗，而且連 query log 都不寫。
# 後果：依賴 AGH 的代理 App 解析不到節點域名 → VPN 隧道起得來卻零流量 →
# 它的看門狗連續失敗後自斷，用戶只看到「連不上」。
#
# 模組原本沒有任何「上游層」的 respawn：service.sh 只在開機拉一次；iptables.sh 的 5 秒
# 守護循環只看「進程在不在＋規則在不在」，重拉時還順帶開關一次飛行模式（閃斷網路）。
# 「進程活著但上游全啞」它完全看不見 —— 本腳本補的就是這個洞。
#
# 探測的核心難點：必須問一個「要走上游、不命中黑名單、也不命中快取」的查詢。
# 拿黑名單域去問會 0.07ms 秒回、永遠報健康，等於做個廢物——實測證據：上游全啞的當下
# 問 ipwho.is 仍是 cost=0s rcode=0 ANCOUNT=1 回 0.0.0.0，而同一時刻問探測名是 rcode=2。
# 做法：隨機子域 probe-<8hex>.invalid-healthcheck.example 問 A 記錄——
#   · 名稱隨機 → 繞開 cache_ttl_max=7200／cache_optimistic（快取永不命中）
#   · .example 不在根區 → 上游必須真的去問才答得出來（實測回覆帶 root-servers.net 的
#     SOA 授權段，證明這是上游給的權威答案，不是 AGH 本地湊的）
# 探測方法（實測出來的，細節見 probe_once／probe_round 上方註解）：
# 設備上沒有 dig/nslookup/host/curl，所以用 printf 八進位轉義手搓 60 位元組 DNS 查詢，
# 走 toybox nc -u 打 AGH 自己的 127.0.0.1:<dns.port>，回覆落地成檔再 xxd 轉 hex 查 ID 與 RCODE。
# 判定：NOERROR(0)／NXDOMAIN(3)＝上游給了權威答案＝活著；沒回覆／SERVFAIL(2)／REFUSED(5)＝死；
# 拿到 0.0.0.0 的 A 記錄＝AGH 本地黑名單應答，不記入好壞。
# 一「輪」連發 3 個隨機名稱（任一有答即算活），連續 3 輪失敗才重啟——單發會因為
# load_balance 只派一條上游＋冷啟動要 11s 而憑空報死，實測踩過。
#
# 設備上跑的是 toybox/POSIX sh，本檔不得使用 bashism。

AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
CONFIG_FILE="$AGH_DIR/scripts/config.prop"
YAML_FILE="$BIN_DIR/data/AdGuardHome.yaml"
MAIN_LOG="$AGH_DIR/agh.log"
# 探測用的暫存檔（查詢封包／回覆），固定檔名：下次探測直接覆寫，行程被殺也不會累積
PKT_FILE="$AGH_DIR/.healthcheck-query.bin"
ANS_FILE="$AGH_DIR/.healthcheck-answer.bin"

# 防止重複啟動（與 iptables.sh／NoAdsService.sh 同一套寫法）
# 注意：pgrep -f 比的是整條 cmdline，所以若有人用 `su -c "sh .../healthcheck.sh"` 這種
# 「外層字串裡也帶著同一個路徑」的方式啟動，外層行程會被一起算進去而讓實例直接退出；
# 要手動除錯就得像 service.sh 那樣直接拉腳本，或經過一层 exec 啟動器。
[ "$(pgrep -f "$0" | wc -l)" -gt 1 ] && exit

log() { echo "$(date '+%F %T') [healthcheck] $1" >> "$MAIN_LOG"; }

# 通知只在「重啟到上限仍不健康」時發一次，不反覆轟炸通知欄
notify() {
    cmd notification post -S bigtext -t "$2" "agh-healthcheck" "$1" >/dev/null 2>&1
}

# 參數可被 config.prop 覆蓋（檔內這幾個預設是註解掉的，所以也允許用環境變數傳入做除錯）
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE" 2>/dev/null
[ -n "$probe_wait" ]      || probe_wait=20       # 單次探測等回覆的硬上限（秒）：要 > yaml 的 upstream_timeout(10s)，否則慢但真的回覆會被誤判成死（實測冷啟動那一發要 11~18s）
[ -n "$probe_attempts" ]  || probe_attempts=3    # 一輪探測裡連發幾個隨機名稱，任一回覆即算這一輪健康
[ -n "$attempt_gap" ]     || attempt_gap=3       # 同一輪內兩次嘗試之間的小間隔
[ -n "$probe_interval" ]  || probe_interval=60   # 健康時的探測間隔
[ -n "$retry_gap" ]       || retry_gap=45        # 已判失敗後，下一輪探測的間隔（30~60）
[ -n "$fail_threshold" ]  || fail_threshold=3    # 連續幾輪失敗才動作，擋單次抖動
[ -n "$max_restart" ]     || max_restart=2       # 一個故障週期內最多重啟幾次，避免上游長期不可達時反覆重啟空轉
[ -n "$start_delay" ]     || start_delay=90      # 開機初期網路還沒就緒，先穩定一下再開始判定
[ -n "$redir_port" ]      || redir_port=5591

# AGH 實際監聽的 DNS 埠以配置檔為準（iptables.sh 用的 redir_port 只是備援）
dns_port() {
    p=$(sed -n '/^dns:/,/^[^ ]/s/^[[:space:]]*port:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$YAML_FILE" 2>/dev/null | head -1)
    case "$p" in
        *[!0-9]*|"") p="$redir_port" ;;
    esac
    case "$p" in
        *[!0-9]*|"") p=5591 ;;
    esac
    printf '%s' "$p"
}

# 有沒有一點網路：飛航模式開著、或所有路由表都沒有 default 路由時，重啟 AGH 也不會
# 讓上游變可用，只會白重啟＋亂發通知，所以這種情況跳過判定。
# 注意方向：用「正面偵測無網」而不是「正面偵測有網」——任何一項檢查失敗都照常探測
# （fail-open），否則這支腳本會在某個 ROM 的 ip/dumpsys 輸出對不上時悄悄變成廢物。
no_network() {
    [ "$(settings get global airplane_mode_on 2>/dev/null | tr -d ' \n\r')" = "1" ] && return 0
    ip route show table all 2>/dev/null | grep -q "default" && return 1
    [ -n "$(dumpsys connectivity 2>/dev/null | sed -n 's/^Active default network: //p' | head -1)" ] && return 1
    if [ "$skip_logged" -eq 0 ]; then
        log "偵測不到任何網路（無 default 路由、無活動預設網路），跳過本輪判定"
        skip_logged=1
    fi
    return 0
}

# 單次探測：回 0=上游有答覆、1=沒答覆(死)、2=回覆無效（不能據此判活）
#
# 為什麼是「寫檔＋輪詢＋自己殺 nc」而不是 `printf | nc | ...` 一條管線：
# 1) 命令代換會等管線裡「所有」行程結束，而 toybox nc 收到一個 UDP 回覆後並不會收工，
#    實測這種寫法每一發都要燒滿外層 timeout（15s），健康時那 0.4s 的延遲完全被浪費；
# 2) nc 的 -w 偶發地會漏讀「剛發完就抵達」的回覆（實測同一時刻輪詢版 6/6 都拿到回覆、
#    管線版有一發拿到 0 位元組），漏讀就等於憑空報死；
# 3) 回覆先落地成檔案，輪詢到檔案非空即判定（健康時延遲回到 ~0.4s），然後直接殺掉 nc——
#    等回覆的時間由這個輪詢上限控制，不靠 nc 的 -w（實測它不會自己退場，見下方註解）。
# 封包先 printf 進暫存檔，是因為命令代換存不下 DNS 封包裡的 NUL 位元組。
probe_once() {
    tag=$(head -c 4 /dev/urandom 2>/dev/null | xxd -p | tr -d ' \n\r')
    [ "${#tag}" -ge 8 ] || return 2
    t0=$(date +%s)
    # 封包：ID=0x1337 RD=1 QDCOUNT=1 ＋ "\016probe-<8hex>"(14) "\023invalid-healthcheck"(19)
    # "\007example"(7) 根標籤 ＋ QTYPE=A QCLASS=IN，共 60 位元組
    printf '\023\067\001\000\000\001\000\000\000\000\000\000\016probe-%s\023invalid-healthcheck\007example\000\000\001\000\001' "$tag" > "$PKT_FILE" || return 2
    : > "$ANS_FILE"
    nc -u 127.0.0.1 "$port" < "$PKT_FILE" > "$ANS_FILE" 2>/dev/null &
    ncpid=$!
    # 用時鐘截止而不是「睡 0.1 秒 × N 次」計數：裝置上每起一個 sleep 行程都有可觀開銷，
    # 實測 150 次迴圈會飄到 18s（比 probe_wait 還久），改成看牆鐘才不會越等越久。
    deadline=$(( $(date +%s) + probe_wait ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        sleep 0.1
        [ -s "$ANS_FILE" ] && break
    done
    resp=$(xxd -p < "$ANS_FILE" 2>/dev/null | tr -d ' \n\r')
    # 殺的必須是 nc 本體：實測 toybox nc 收過一個 UDP 回覆後不會自己收工，而 -w 在「沒回覆」
    # 時也不會讓它退出——先前外面套一層 timeout 的寫法，殺掉 timeout 等於把 nc 變成孤兒，
    # 那些 nc 會永久掛在 127.0.0.1:5591 上（實測 15:09 漏的那一發到 15:26 還在），
    # 一天洩漏 1440 個行程。所以管線裡不留 timeout，$! 直接就是 nc，殺完再 wait 收屍。
    kill -9 "$ncpid" 2>/dev/null
    wait "$ncpid" 2>/dev/null
    probe_cost=$(( $(date +%s) - t0 ))
    # 回覆至少要有 header(12B)=24 個 hex 字元
    [ "${#resp}" -ge 24 ] || return 1
    # 前 4 個 hex 是查詢 ID，第 8 個 hex 是 RCODE 的低 4 位元
    [ "$(printf '%s' "$resp" | cut -c1-4)" = "1337" ] || return 1
    # RDATA=0.0.0.0（rdlength 0004 + 00000000）＝AGH 自己的黑名單預設應答，這種回覆不能證明上游活著
    case "$resp" in
        *000400000000*) return 2 ;;
    esac
    case "$(printf '%s' "$resp" | cut -c8)" in
        0|3) return 0 ;;
        *)   return 1 ;;
    esac
}

# 一輪探測：連發 probe_attempts 個隨機名稱，只要有一發拿到上游答覆這輪就算活。
# 為什麼不能只問一次（手機實測結論）：
# · upstream_mode 是 load_balance，一發查詢只會被派給池裡的一條上游，池子「半死」
#   （一條好一條壞）時單發探測有近一半機率打壞，連續三發打壞的機率就有 12.5%，
#   實測這樣真的把「能用」誤判成「全啞」並白重啟了一次 AGH；
# · 冷啟動很貴：空檔久了第一發要重做 bootstrap 解析＋TCP+TLS，實測耗時 11s >
#   upstream_timeout(10s) 直接被判死，而緊接其後的第二發只要 0.4s。
# 連發三次（任一成功即算健康）之後，「半死＋冷啟動」要連壞 3×3 次才會觸發重啟，
# 而「真的全啞」依然每發都拿不到回覆——放寬的是抖動，沒放寬判定條件本身。
probe_round() {
    a=1
    round_cost=0
    while [ "$a" -le "$probe_attempts" ]; do
        probe_once
        rc=$?
        # round_cost 記「這一輪最慢的一發」：15s 表示根本沒回覆，0~1s 表示 AGH 回了 SERVFAIL
        # 之類的錯誤碼——兩種「死法」在日誌裡分得開，事後要調參才不用猜。
        [ "$probe_cost" -gt "$round_cost" ] && round_cost="$probe_cost"
        [ "$rc" -ne 1 ] && return "$rc"
        [ "$a" -lt "$probe_attempts" ] && sleep "$attempt_gap"
        a=$((a + 1))
    done
    return 1
}

restart_agh() {
    log "連續 $fail_threshold 輪（每輪 $probe_attempts 發）無上游應答，重啟 AdGuardHome（本故障週期第 $restarts 次，上限 $max_restart）"
    # 必須 -9：優雅關閉（TERM）時 AGH 會把記憶體裡的概念覆寫回 AdGuardHome.yaml，
    # 直接蓋掉用戶對配置檔的改動（本模組實測踩過）。
    pkill -9 -x AdGuardHome
    # 空窗壓到最短：iptables.sh 的 5 秒守護循環若正好在空窗取樣到「進程丟失」，它除了
    # 重拉還會開關一次飛行模式（閃斷用戶網路）；本腳本自身絕不碰飛行模式。
    sleep 1
    # 已經被守護循環拉起來了就別雙開——兩個實例搶 5591/3000 埠會 panic 循環重啟
    if pgrep -x AdGuardHome >/dev/null; then
        log "AdGuardHome 已由守護循環拉起，不重複啟動"
        return 0
    fi
    # -w 必帶：缺 workdir 時 AGH 進「首次安裝向導」並因 3000 埠被佔而 panic 循環重啟
    export SSL_CERT_DIR="/system/etc/security/cacerts/"
    "$BIN_DIR/AdGuardHome" --no-check-update -w "$BIN_DIR/data" >/dev/null 2>&1 &
    return 0
}

fails=0
restarts=0
gave_up=0
notified=0
skip_logged=0
invalid_logged=0
probe_cost=0
round_cost=0

sleep "$start_delay"
port=$(dns_port)
log "上游探測啟動（目標 127.0.0.1:$port，單發等 ${probe_wait}s，一連 $probe_attempts 發任一有答即算健康，連續 $fail_threshold 輪失敗才重啟，一輪故障最多重啟 $max_restart 次，間隔 ${probe_interval}s）"

while :; do
    # config.prop 可能在運行中被改（例如換劫持埠）
    [ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE" 2>/dev/null
    [ -n "$probe_wait" ]     || probe_wait=20
    [ -n "$probe_attempts" ] || probe_attempts=3
    [ -n "$attempt_gap" ]    || attempt_gap=3
    [ -n "$probe_interval" ] || probe_interval=60
    [ -n "$retry_gap" ]      || retry_gap=45
    [ -n "$fail_threshold" ] || fail_threshold=3
    [ -n "$max_restart" ]    || max_restart=2
    port=$(dns_port)

    if no_network; then
        sleep "$probe_interval"
        continue
    fi
    skip_logged=0

    probe_round
    rc=$?

    if [ "$rc" -eq 0 ]; then
        # 上游有答覆（NOERROR／NXDOMAIN）；只在「剛從故障裡走出來」時留一行，健康時完全不寫日誌
        if [ "$fails" -gt 0 ] || [ "$gave_up" -eq 1 ] || [ "$notified" -eq 1 ]; then
            log "上游已恢復應答（本故障週期累計失敗 $fails 輪、自動重啟 $restarts 次），計數歸零、重新武裝"
        fi
        fails=0
        restarts=0
        gave_up=0
        notified=0
        invalid_logged=0
        sleep "$probe_interval"
        continue
    fi

    if [ "$rc" -eq 2 ]; then
        # 拿到的是黑名單式應答＝這個探測名稱對當前規則無效，不能拿去說「健康」也不能說「死」
        if [ "$invalid_logged" -eq 0 ]; then
            log "探測回覆為本地黑名單應答（0.0.0.0），本輪不計好壞——請檢查過濾規則是否命中 invalid-healthcheck.example"
            invalid_logged=1
        fi
        sleep "$retry_gap"
        continue
    fi

    # 上游無應答（這一輪 $probe_attempts 發全都沒回）
    invalid_logged=0
    fails=$((fails + 1))
    log "HC_FAIL $fails/$fail_threshold target=127.0.0.1:$port attempts=$probe_attempts round_cost=${round_cost}s"

    if [ "$fails" -lt "$fail_threshold" ]; then
        sleep "$retry_gap"
        continue
    fi

    if [ "$gave_up" -eq 1 ]; then
        # 已經重啟到上限、之後又湊滿一次連續失敗——這才是「重啟也沒用」的實證：
        # 上游本身不可達（線路／對端掛了），繼續重啟只是空轉。停止重啟、留日誌＋通知一次，
        # 之後低頻複查等上游自己恢復（恢復時上面 rc=0 分支會把整個狀態重新武裝）。
        if [ "$notified" -eq 0 ]; then
            log "連續重啟 $max_restart 次後上游仍無應答，停止自動重啟，每 10 分鐘複查等上游恢復"
            notify "AdGuardHome 上游重啟 $max_restart 次仍無回應，已停止自動重啟（詳見 agh.log）" "AGH 上游異常"
            notified=1
        fi
        fails=0
        sleep 600
        continue
    fi

    restarts=$((restarts + 1))
    restart_agh
    fails=0
    [ "$restarts" -ge "$max_restart" ] && gave_up=1
    # 剛重啟完，給它一點起時間（DoH 要先經 bootstrap 解析上游域名）
    sleep 15
done
