#!/system/bin/sh
SCRIPTS_DIR="/data/adb/agh/scripts"
MOD_PATH=${MODPATH:-/data/adb/modules/AdGuardHome}
LAST_LOCALE="INIT"
# 允許環境變數改根目錄僅供 /tmp 沙箱演練用；設備上走預設絕對路徑。
AGH_DIR="${AGH_DIR:-/data/adb/agh}"

# 防止重複啟動：pidfile ＋ /proc/<pid>/cmdline 驗證（同 healthcheck.sh 那套模式）。
# 舊寫法 `[ "$(pgrep -f "$0" | wc -l)" -gt 1 ] && exit` 是**平台相關**的脆弱守門：
# 在 GNU pgrep（PC 沙箱／CI／任何 Linux 機）上，命令代換會派生一個 cmdline 與本腳本
# 一模一樣、PID 不同的子 shell，把自己數成兩個 → 直接秒退；在設備的 toybox 上實測
# **不會**秒退（證據：2026-09-27 本機的 iptables.sh 守護循環活著，還把飛行模式連開關三次）。
# 所以換 pidfile 是「把運氣換成確定」，不是「這支以前沒跑」——設備行為不該因此改變。
# 本腳本主循環在前臺（由 service.sh 用 & 拉起），所以 $$ 就是那個存活循環；旧 PID 被複用時 /proc 驗證不會擋死新實例。
PIDFILE="$AGH_DIR/ModuleMOD.pid"
oldpid=$(cat "$PIDFILE" 2>/dev/null)
if [ -n "$oldpid" ] && grep -q "ModuleMOD.sh" "/proc/$oldpid/cmdline" 2>/dev/null; then
    exit
fi
echo "$$" > "$PIDFILE"

# 语言检测相关
while true; do
  CURRENT_LOCALE=$(getprop persist.sys.locale)
  [ -z "$CURRENT_LOCALE" ] && CURRENT_LOCALE="zh" 
  if [ "$LAST_LOCALE" = "INIT" ] || [ "$LAST_LOCALE" != "$CURRENT_LOCALE" ]; then
    if echo "$CURRENT_LOCALE" | grep -qi "zh"; then
      sed -i "s|^description=.*|description=DNS层面过滤广告、防DNS劫持，开机时端口随机化，管理器页面点击操作按钮进入，不要私自更改内置规则和配置，账号和密码均为root|" "$MOD_PATH/module.prop"
    else
      sed -i "s|^description=.*|description=DNS-level ad blocking and anti-DNS hijacking. Port Randomization at Startup. Click the action button on the Manager page to proceed. Do not modify built-in rules or configuration. login: root/root.|" "$MOD_PATH/module.prop"
    fi
    LAST_LOCALE="$CURRENT_LOCALE"
fi

# 延迟启动
  sleep 5
done
