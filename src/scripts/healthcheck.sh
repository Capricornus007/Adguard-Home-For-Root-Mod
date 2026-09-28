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
# 「有回覆」還要再分兩種結論（2026-09-27 定案，重啟能不能救就分在這裡）：
# · 死掉＝需要上游的查詢無回覆／SERVFAIL／REFFAIL。線路或上游對端故障，AGH 內部
#   狀態也可能卡死，重啟有可能救 → 走重啟路徑（有節流與上限）。
# · 被投毒＝秒回、但回的是假 IP。境內線路在途注入的實測假值形如 157.240.7.20、
#   185.45.5.35（AAAA 常見 2001::1）。這是上游／線路的鍋，**重啟完全沒用**，
#   所以投毒只記日誌＋發一次通知，絕不重啟。判據用「誠實性檢查」：問 dns.google
#   （Google 自己的域、誠實上游必回 8.8.8.8/8.8.4.4，且在本模組 ignore_dest_list
#   豁免清單上不會被本地劫持），拿到非預期的 A 記錄即記一筆可疑、湊滿門檻才定罪。
# · 黑名單域名秒回 0.0.0.0 是**正常行為**，既不當健康證據也不當故障證據（rc=2 不計）。
#
# 設備上跑的是 toybox/POSIX sh，本檔不得使用 bashism。

# 允許用環境變數改根目錄：僅供假環境演練（/tmp 下的沙箱）使用；
# 設備上没人設這個變數，走預設絕對路徑，與 service.sh 拉的實際位置一致。
AGH_DIR="${AGH_DIR:-/data/adb/agh}"
BIN_DIR="$AGH_DIR/bin"
CONFIG_FILE="$AGH_DIR/scripts/config.prop"
YAML_FILE="$BIN_DIR/data/AdGuardHome.yaml"
MAIN_LOG="$AGH_DIR/agh.log"
# 探測用的暫存檔（查詢封包／回覆），固定檔名：下次探測直接覆寫，行程被殺也不會累積
PKT_FILE="$AGH_DIR/.healthcheck-query.bin"
ANS_FILE="$AGH_DIR/.healthcheck-answer.bin"

# 防止重複啟動：用 pidfile，不用 `pgrep -f` 數 cmdline。原因（PC 沙箱演練實測踩中）：
# 「$(pgrep ... | wc -l)」的命令代換會派生一個 cmdline 與主體一模一樣、但 PID 不同
# 的子 shell，$$ 標的是主體、awk 濾不掉它，自己把自己判成兩個實例秒退；祖先行程的
# cmdline 只要剛好帶到本檔路徑（如 `su -c "sh .../healthcheck.sh"` 手工啟動）也會
# 誤殺真實例。pidfile 另加一道 /proc/<pid>/cmdline 驗證：舊 PID 若已被別的傢伙用走
# （重開機後 pidfile 殘留的情境），不會把新實例擋死。與 iptables.sh 守門同目的、寫法不同。
PIDFILE="$AGH_DIR/healthcheck.pid"
oldpid=$(cat "$PIDFILE" 2>/dev/null)
if [ -n "$oldpid" ] && grep -q "healthcheck" "/proc/$oldpid/cmdline" 2>/dev/null; then
    exit
fi
echo $$ > "$PIDFILE"

log() { echo "$(date '+%F %T') [healthcheck] $1" >> "$MAIN_LOG"; }

# 全倉「唯一」的通知出口：只在確定要提醒用戶時呼叫，呼叫端自己用 xxx_notified 鎖成一次，
# 本函式不疊加節流。簽名 notify <內文> <標題>（沿用 e402887 以來的參數順序，呼叫端不改）。
#
# 為什麼不能像以前那樣只寫死 `cmd notification post`：本 ROM 能不能真的彈出、root shell
# 內建的 cmd/am 是否被裁掉，這一輪無法在不碰手機的前提下實證。賭它一定彈＝可能靜默失效，
# 正是用戶最討厭的形態。所以改成「運行期逐級探測、都不行就保底寫日誌」，且絕不讓本腳本崩或卡：
#   路徑 A cmd notification post（Android shell 內建通知，root 免額外授權；最可能真彈出）
#   路徑 B am broadcast（部分 ROM 有對應接收端時才彈，best-effort 次選；通常無接收端＝不彈，
#          但仍比整條通知鏈直接消失好，且 am 也在設備必存在清單內）
#   路徑 C 只寫日誌（保底，一定能留痕——即使 A/B 都不彈，用戶仍可從 agh.log 看到這一行）
# 候選只用「设备上必然存在」的（cmd/am/log 檔），不准引入任何需要安裝／授權的東西。
# 每條都用 command -v 先篩存在性、輸出丟棄、失敗就往下退；選中哪條寫進日誌一行做留痕。
_run_guarded() {
    # 有 toybox timeout 就加 5 秒保險，避免某些 ROM 上 cmd/am 卡死拖垮整個探測循環；
    # 沒有 timeout 就直接跑（呼叫端已 2>/dev/null，最壞是該次通知失敗退到日誌）。
    if command -v timeout >/dev/null 2>&1; then
        timeout 5 "$@"
    else
        "$@"
    fi
}

notify() {
    _n_body="$1"; _n_title="$2"; _n_path="log(保底)"
    if command -v cmd >/dev/null 2>&1 && \
        _run_guarded cmd notification post -S bigtext -t "$_n_title" "agh-healthcheck" "$_n_body" >/dev/null 2>&1; then
        _n_path="cmd-notification"
    # 刻意**不**放 `am broadcast` 當次選：無接收端的 broadcast 照樣回 exit 0，
    # 日誌會寫「出口=am-broadcast」但通知欄什麼都沒彈 —— 那是假陽性，
    # 會讓事後看日誌的人以為通知鏈是通的。寧可直接落到 log(保底)。
    fi
    # 無論走哪條路徑，都固定留一行「這次用的是哪條路徑」＋通知內容，事後好核對、也保底可见
    echo "$(date '+%F %T') [healthcheck] 通知[出口=$_n_path]：$_n_title｜$_n_body" >> "$MAIN_LOG"
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
[ -n "$poison_check" ]    || poison_check=1      # 投毒判定總開關；想關掉設 0（只影響誠實性檢查，重啟邏輯不受波及）
[ -n "$poison_check_aaaa" ] || poison_check_aaaa=1 # AAAA(IPv6) 誠實性檢查開關，預設開。理由：用戶明確在意 IPv6，境內上游會回假 v6（實測形態如 2001::1），v6 假值必須能定罪才不辜負 v6 支援；而「投毒」分支本來就不重啟（重啟救不了鏈路注入），所以加 AAAA 檢查零風險，最壞只是多一條不重啟的日誌／通知。設 0 可單關 v6、保留 v4 判定。
[ -n "$poison_wait" ]     || poison_wait=5       # 誠實性檢查等回覆秒數：投毒是鏈路在途注入、回得飞快（0.x 秒級），5s 綽綽有餘；真答案偶爾慢過這個上限只會被判「無法判定」而不是投毒——寧可漏判也不亂扣帽子，更不會觸發重啟
[ -n "$poison_threshold" ] || poison_threshold=2 # 累計幾輪假回覆才定罪投毒：單發一次假 IP 可能是快取/anycast 邊界，要兩次獨立證據才報，避免驚呼狼來了

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

# 通用發送器：呼叫端先把查詢封包寫進 $PKT_FILE，並設好全域 t0／wait_budget／want_id；
# 回覆 hex 存入全域 resp，probe_cost 記這一發耗時。回 0=拿到 ID 相符的回覆、1=沒回覆或 ID 不符。
#
# 為什麼是「寫檔＋輪詢＋自己殺 nc」而不是 `printf | nc | ...` 一條管線：
# 1) 命令代換會等管線裡「所有」行程結束，而 toybox nc 收到一個 UDP 回覆後並不會收工，
#    實測這種寫法每一發都要燒滿外層 timeout（15s），健康時那 0.4s 的延遲完全被浪費；
# 2) nc 的 -w 偶發地會漏讀「剛發完就抵達」的回覆（實測同一時刻輪詢版 6/6 都拿到回覆、
#    管線版有一發拿到 0 位元組），漏讀就等於憑空報死；
# 3) 回覆先落地成檔案，輪詢到檔案非空即判定（健康時延遲回到 ~0.4s），然後直接殺掉 nc——
#    等回覆的時間由這個輪詢上限控制，不靠 nc 的 -w（實測它不會自己退場，見下方註解）。
run_probe() {
    : > "$ANS_FILE"
    nc -u 127.0.0.1 "$port" < "$PKT_FILE" > "$ANS_FILE" 2>/dev/null &
    ncpid=$!
    # 用時鐘截止而不是「睡 0.1 秒 × N 次」計數：裝置上每起一個 sleep 行程都有可觀開銷，
    # 實測 150 次迴圈會飄到 18s（比 probe_wait 還久），改成看牆鐘才不會越等越久。
    deadline=$(( t0 + wait_budget ))
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
    # 回覆至少要有 header(12B)=24 個 hex 字元；前 4 個 hex 是查詢 ID
    [ "${#resp}" -ge 24 ] || return 1
    [ "$want_id" = "$(printf '%s' "$resp" | cut -c1-4)" ] || return 1
    return 0
}

# 單次存活探測：回 0=上游有答覆、1=沒答覆(死)、2=回覆無效（不能據此判活）
# 封包先 printf 進暫存檔，是因為命令代換存不下 DNS 封包裡的 NUL 位元組。
probe_once() {
    tag=$(head -c 4 /dev/urandom 2>/dev/null | xxd -p | tr -d ' \n\r')
    [ "${#tag}" -ge 8 ] || return 2
    t0=$(date +%s)
    # 封包：ID=0x1337 RD=1 QDCOUNT=1 ＋ "\016probe-<8hex>"(14) "\023invalid-healthcheck"(19)
    # "\007example"(7) 根標籤 ＋ QTYPE=A QCLASS=IN，共 60 位元組
    printf '\023\067\001\000\000\001\000\000\000\000\000\000\016probe-%s\023invalid-healthcheck\007example\000\000\001\000\001' "$tag" > "$PKT_FILE" || return 2
    wait_budget="$probe_wait"
    want_id="1337"
    run_probe || return 1
    # RDATA=0.0.0.0（rdlength 0004 + 00000000）＝AGH 自己的黑名單預設應答，這種回覆不能證明上游活著
    case "$resp" in
        *000400000000*) return 2 ;;
    esac
    # 第 8 個 hex 是 RCODE 的低 4 位元
    case "$(printf '%s' "$resp" | cut -c8)" in
        0|3) return 0 ;;
        *)   return 1 ;;
    esac
}

# 八位 hex → 點分四段（toybox/GNU printf 都吃 0x 常數，不用 bashism 的字串切片）
ipdot() {
    h="$1"
    printf '%d.%d.%d.%d' \
        "0x$(printf '%s' "$h" | cut -c1-2)" "0x$(printf '%s' "$h" | cut -c3-4)" \
        "0x$(printf '%s' "$h" | cut -c5-6)" "0x$(printf '%s' "$h" | cut -c7-8)"
}

# 誠實性檢查（投毒判定）：問 dns.google 的 A 記錄。它是 Google 自己的域，誠實上游
# 一定回 8.8.8.8/8.8.4.4（這組合從 2016 年用到現在沒變過，比 142.251.x 那類會隨
# Google 調度的 anycast 網段更好當基準）；它不在黑名單裡，也不吃「隨機子域快取永不
# 命中」那套——回什麼就代表上游鏈路給了什麼。境內在途注入的特徵是「飛快回一個境內
# 假 IP」（實測假值 157.240.7.20、185.45.5.35，AAAA 常見 2001::1，這裡只問 A）。
# 回傳：0=誠實；1=假 IP（投毒證據）；2=無法判定（沒回覆／0.0.0.0 本地封應答／無 A
# 記錄——不據此定罪，死活交給存活探測判）；3=對既存域名給權威負面應答（NXDOMAIN/
# SERVFAIL/REFUSED）——正常解析器不會對 dns.google 這樣答，同樣算投毒證據。
# 另設全域 honest_local_block：1＝這次「無法判定」是因為本地規則把 dns.google 自己攔了
# （拿到 0.0.0.0）或完全查不到 A 記錄——這是用戶最討厭的「靜默壞掉」形態，主循環據此
# 一次性提示（見 ggl_hint_done）；0＝沒回覆／誠實／定罪（沒回覆屬鏈路問題，不歸因本地規則）。
# 定罪後**不重啟**：投毒發生在鏈路／上游端，重啟 AGH 救不了，狂重啟只會更糟。
probe_honesty() {
    honest_local_block=0
    # 封包：ID=0x1338 RD=1 QDCOUNT=1 ＋ "\003dns" "\006google" 根標籤 ＋ QTYPE=A QCLASS=IN
    printf '\023\070\001\000\000\001\000\000\000\000\000\000\003dns\006google\000\000\001\000\001' > "$PKT_FILE" || return 2
    t0=$(date +%s)
    wait_budget="$poison_wait"
    want_id="1338"
    run_probe || return 2
    case "$resp" in
        *000400000000*)
            honest_detail="回覆 0.0.0.0＝本地過濾規則攔了 dns.google（不是投毒證據，請檢查規則）"
            honest_local_block=1
            return 2 ;;
    esac
    rc4=$(printf '%s' "$resp" | cut -c8)
    case "$rc4" in
        0) ;;
        2|3|5) honest_detail="rcode=$rc4：dns.google 不該收到權威負面應答"; return 3 ;;
        *) honest_detail="rcode=$rc4 無法歸類"; return 2 ;;
    esac
    # A 記錄 RDATA：TYPE(0001)+CLASS(0001)+TTL(8hex)+RDLENGTH(0004)+IP(8hex)。
    # 問題段結尾的 "00010001" 後面沒有 TTL/RDLENGTH/IP 可配，不會誤配。
    ips=$(printf '%s' "$resp" | grep -oE '00010001[0-9a-f]{8}0004[0-9a-f]{8}' | sed 's/^00010001[0-9a-f]\{8\}0004//')
    [ -n "$ips" ] || { honest_detail="NOERROR 但沒有可解析的 A 記錄（可能只有 CNAME）"; honest_local_block=1; return 2; }
    for ip in $ips; do
        case "$ip" in
            08080808|08080404) ;;
            *) honest_detail="$(ipdot "$ip")（預期 8.8.8.8/8.8.4.4，hex 原值 $ip）"; return 1 ;;
        esac
    done
    return 0
}

# 八組 4 位 hex → 冒號分隔的 v6 字串（僅供日誌可讀，不做 :: 壓縮）。
# POSIX sh 沒字串切片，逐段 cut，跟 ipdot 同思路。
v6pretty() {
    h="$1"
    printf '%s:%s:%s:%s:%s:%s:%s:%s' \
        "$(printf '%s' "$h" | cut -c1-4)" "$(printf '%s' "$h" | cut -c5-8)" \
        "$(printf '%s' "$h" | cut -c9-12)" "$(printf '%s' "$h" | cut -c13-16)" \
        "$(printf '%s' "$h" | cut -c17-20)" "$(printf '%s' "$h" | cut -c21-24)" \
        "$(printf '%s' "$h" | cut -c25-28)" "$(printf '%s' "$h" | cut -c29-32)"
}

# 誠實性檢查的 IPv6 版（AAAA）：同問 dns.google，但 QTYPE=AAAA(28)。誠實上游必回
# 2001:4860:4860::8888 / ::4444（Google 的 v6 任播，多年未變，跟 v4 的 8.8.8.8/8.8.4.4
# 一樣好當死基準）；境內注入的假 v6 形如 2001::1。回傳：
#   0=誠實；1=假 v6（投毒證據，進同一個 poison_fails 計數、湊滿門檻才定罪、照樣不重啟）；
#   2=無法判定（不定罪也不平反）。
# 關鍵保守原則：v6「拿不到」絕不等於投毒——很多上游不提供 v6、或鏈路根本沒 v6，正常
# 表現就是 NOERROR 但無 AAAA 記錄，或 SERVFAIL/REFUSED，甚至本地黑名單回 :: 全零。這些
# 一律判「無法判定」。只有「明確回了一條非預期、又非全零的 AAAA」（如 2001::1）才當投毒。
# 因投毒分支本來就不重啟，加這支對存活／重啟邏輯零風險，只是把用戶在意的 v6 假值纳入定罪。
probe_honesty_aaaa() {
    honest_detail_aaaa=""
    # 封包同 A 版，只差 QTYPE=0x001C（八進位 \000\034）；ID 用 0x1339 與 A 版區隔
    printf '\023\071\001\000\000\001\000\000\000\000\000\000\003dns\006google\000\000\034\000\001' > "$PKT_FILE" || return 2
    t0=$(date +%s)
    wait_budget="$poison_wait"
    want_id="1339"
    run_probe || return 2
    rc4=$(printf '%s' "$resp" | cut -c8)
    # v6 版：只有 NOERROR 才往下拆記錄。SERVFAIL/NXDOMAIN/REFUSED 對 AAAA 可能只是
    # 「上游／鏈路不提供 v6」的正常結果，不能拿去定罪（與 v4 的權威負面＝投毒相反）。
    case "$rc4" in
        0) ;;
        *) honest_detail_aaaa="rcode=$rc4（v6 可能本就不提供，非投毒證據）"; return 2 ;;
    esac
    # AAAA RDATA：TYPE(001c)+CLASS(0001)+TTL(8hex)+RDLENGTH(0010)+IPv6(32hex)。
    v6s=$(printf '%s' "$resp" | grep -oE '001c0001[0-9a-f]{8}0010[0-9a-f]{32}' | sed 's/^001c0001[0-9a-f]\{8\}0010//')
    [ -n "$v6s" ] || { honest_detail_aaaa="NOERROR 但無 AAAA 記錄（上游／鏈路可能沒 v6）"; return 2; }
    seen_real=0
    for v6 in $v6s; do
        case "$v6" in
            # :: 全零＝AGH 本地黑名單的 v6 預設應答（對應 v4 的 0.0.0.0），不據此定罪
            00000000000000000000000000000000)
                honest_detail_aaaa="回覆 ::＝本地規則攔了 dns.google 的 AAAA"; return 2 ;;
            # 誠實基準（Google v6 任播）；跳過繼續看其他記錄
            20014860486000000000000000008888|20014860486000000000000000004444)
                seen_real=1 ;;
            # 其餘非預期值＝假 v6（如 2001::1）＝投毒證據
            *)
                honest_detail_aaaa="$(v6pretty "$v6")（預期 2001:4860:4860::8888/::4444，hex 原值 $v6）"
                return 1 ;;
        esac
    done
    [ "$seen_real" -eq 1 ] && return 0
    return 2
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
poison_fails=0
poison_active=0
poison_notified=0
ggl_hint_done=0
probe_cost=0
round_cost=0
# run_probe 的介面變數（探測回覆 hex／判定明細）
t0=0
wait_budget=0
want_id=""
resp=""
honest_detail=""
honest_detail_aaaa=""
honest_local_block=0

sleep "$start_delay"
port=$(dns_port)
log "上游探測啟動（目標 127.0.0.1:$port，單發等 ${probe_wait}s，一連 $probe_attempts 發任一有答即算健康，連續 $fail_threshold 輪失敗才重啟，一輪故障最多重啟 $max_restart 次，間隔 ${probe_interval}s，投毒判定 $poison_check（dns.google 誠實性檢查，v6/AAAA $poison_check_aaaa，累計 $poison_threshold 輪假回覆只通知不重啟））"

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
    [ -n "$poison_check" ]   || poison_check=1
    [ -n "$poison_check_aaaa" ] || poison_check_aaaa=1
    [ -n "$poison_wait" ]    || poison_wait=5
    [ -n "$poison_threshold" ] || poison_threshold=2
    port=$(dns_port)

    if no_network; then
        sleep "$probe_interval"
        continue
    fi
    skip_logged=0

    probe_round
    rc=$?

    if [ "$rc" -eq 0 ]; then
        # 上游有答覆≠答覆誠實。存活之後補一發誠實性檢查：境內注入會「秒回假 IP／假 v6」，
        # 這種情況重啟完全救不了（鍋在鏈路／上游端），所以只記日誌＋整段投毒只通知
        # 一次，並**跳過下面的重新武裝**——投毒中的「有回應」不能拿來證明上游健康。
        if [ "$poison_check" -eq 1 ]; then
            probe_honesty
            hc=$?
            # v4 定罪了才省下一發 v6；否則照問 v6（用戶在意 IPv6，假 v6 也要能定罪）。
            hc6=2
            if [ "$hc" -ne 1 ] && [ "$hc" -ne 3 ] && [ "$poison_check_aaaa" -eq 1 ]; then
                probe_honesty_aaaa
                hc6=$?
            fi
            # 綜合判定：v4 假 IP／權威負面，或 v6 明確假值，任一到手都算投毒證據。
            poison_hit=0
            if [ "$hc" -eq 1 ] || [ "$hc" -eq 3 ]; then poison_hit=1; fi
            if [ "$hc6" -eq 1 ]; then poison_hit=1; fi

            if [ "$poison_hit" -eq 1 ]; then
                # 組一句明細：把定罪的那一側寫進去（v4／v6 都可能，兩側都中就把兩側都寫）。
                poison_detail=""
                poison_sep=""
                if [ "$hc" -eq 1 ] || [ "$hc" -eq 3 ]; then
                    poison_detail="A：$honest_detail"
                    poison_sep=" / "
                fi
                if [ "$hc6" -eq 1 ]; then
                    poison_detail="${poison_detail}${poison_sep}AAAA：${honest_detail_aaaa}"
                fi
                poison_fails=$((poison_fails + 1))
                # 定罪前逐輪留痕（要看得見累積過程）；定罪之後轉靜默低頻複查，
                # 免得長期投毒把 agh.log 刷爆——通知本身已由 poison_notified 鎖成一次。
                if [ "$poison_fails" -le "$poison_threshold" ]; then
                    log "HC_POISON $poison_fails/$poison_threshold dns.google 回覆異常（$poison_detail）——投毒是鏈路／上游的鍋，重啟無效，不重啟"
                fi
                if [ "$poison_fails" -ge "$poison_threshold" ] && [ "$poison_active" -eq 0 ]; then
                    poison_active=1
                    if [ "$poison_notified" -eq 0 ]; then
                        notify "上游 DNS 回覆疑遭投毒（$poison_detail）。重啟無法解決，請檢查線路／上游。詳見 agh.log" "AGH 上游投毒疑慮"
                        poison_notified=1
                    fi
                fi
                sleep "$probe_interval"
                continue
            fi
            # 沒定罪：v4 或 v6 任一拿到誠實答案即平反、歸零、重新武裝（也解除本地攔截提示鎖）。
            if [ "$hc" -eq 0 ] || [ "$hc6" -eq 0 ]; then
                if [ "$poison_active" -eq 1 ]; then
                    log "上游回覆恢復誠實（投毒警報解除，此前累計可疑 $poison_fails 輪），計數歸零、重新武裝"
                fi
                poison_fails=0
                poison_active=0
                poison_notified=0
                ggl_hint_done=0
            else
                # v4、v6 都「無法判定」。這裡補上用戶要的「不能再完全靜默」：
                # 若 v4 側是因為本地規則把 dns.google 攔了（0.0.0.0）或完全查不到 A 記錄
                # （honest_local_block=1），一次性提示去檢查規則；同一場攔截期間不重複刷屏，
                # 等下次能判定（v4/v6 誠實）時由上面那支 ggl_hint_done=0 重新武裝。
                # 反過來說「沒回覆」屬鏈路問題（honest_local_block=0），不歸因本地規則，
                # 並把鎖鬆開，好讓之後真被攔時能重新提示一次。
                if [ "$honest_local_block" -eq 1 ]; then
                    if [ "$ggl_hint_done" -eq 0 ]; then
                        log "HC_BLOCKED_HINT dns.google 誠實性檢查拿不到有效答案（$honest_detail）——通常是本地過濾規則把 dns.google 自己攔了，投毒判定與存活／重啟都不受影響，但請檢查規則（同一場攔截只提示這一次）"
                        notify "健康探測的誠實性檢查被本地規則攔掉（$honest_detail），投毒判定失效但解析與過濾不受影響，請檢查是否誤攔 dns.google" "AGH 探測規則衝突"
                        ggl_hint_done=1
                    fi
                else
                    ggl_hint_done=0
                fi
                # 兩者都無法判定不動投毒計數：沒證據既不定罪也不平反
            fi
        fi
        # 上游有答覆（NOERROR／NXDOMAIN）且誠實性檢查通過；只在「剛從故障裡走出來」時留一行，健康時完全不寫日誌
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
