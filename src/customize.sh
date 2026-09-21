#!/system/bin/sh
SKIPUNZIP=1

# 多语言检测
locale=$(getprop persist.sys.locale | tr '[:upper:]' '[:lower:]')
[ -z "$locale" ] && locale="zh"
ui_print "- $locale"
case $locale in
  en*) language=en ;;
  *)   language=zh ;;
esac
i18n_print() {
  [ "$language" = "zh" ] && ui_print "$2" || ui_print "$1"
}

# 检测所有Hosts模块
i18n_print "- Checking for Hosts modules" "- 正在检测Hosts模块"
found_hosts=false;for module in /data/adb/modules/*;do [ -f "$module/system/etc/hosts" ]&&[ -f "$module/module.prop" ]&&{ [ "$found_hosts" = false ]&&i18n_print "- Found Hosts modules, auto-removing:" "- 发现Hosts模块，正在自动移除:"&&found_hosts=true;ui_print "  $(grep_prop name "$module/module.prop")";touch "$module/remove";};done
[ "$found_hosts" = true ]&&i18n_print "- Conflicting modules have been marked for removal. Please reboot after installation." "- 冲突模块已标记移除，安装完成后请重启设备。"

AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
BACKUP_DIR="$AGH_DIR/backup"
ADGPATH="/data/adb/modules/AdGuardHome"
PROXY_SCRIPT="$AGH_DIR/scripts/ProxyConfig.sh"

i18n_print "- Extracting basic module files" "- 正在解压模块基本文件"
for file in uninstall.sh module.prop service.sh action.sh; do
  unzip -o "$ZIPFILE" "$file" -d "$MODPATH"
done

# 正在停止ProxyConfig
[ -f "$AGH_DIR/scripts/ProxyConfig.sh" ] && {
    i18n_print "- Stopping ProxyConfig process" "- 正在终止ProxyConfig进程"
    pkill -9 "ProxyConfig"
}

# 检查并停止运行中的进程
if [ -d "$AGH_DIR" ]; then
i18n_print "- Stopping all AdGuard Home processes" "- 正在终止AdGuard Home进程"
pkill -9 "AdGuardHome"
fi

# 正在停止NoAdsService
[ -f "$AGH_DIR/scripts/NoAdsService.sh" ] && {
    i18n_print "- Stopping NoAdsService process" "- 正在终止NoAdsService进程"
    pkill -9 "NoAdsService"
}

# 正在停止ProxyConfig
[ -f "$AGH_DIR/scripts/ProxyConfig.sh" ] && {
    i18n_print "- Stopping ProxyConfig process" "- 正在终止ProxyConfig进程"
    pkill -9 "ProxyConfig"
}

# 删除被锁定的残留文件
[ -f "$AGH_DIR/scripts/NoAdsService.sh" ] && {
    i18n_print "- Removing locked residual files" "- 正在删除被锁定的残留文件"
    local c=0 u=0 p;while IFS= read -r p;do [ -n "$p" ]&&[ -e "$p" ]&&while IFS= read -r f;do c=$((c+1));if [ -d "$f" ];then lsattr -d "$f" |grep -q "i-"&&{ chattr -i "$f";rmdir "$f"&&u=$((u+1));} else lsattr "$f" |grep -q "i-"&&{ chattr -i "$f";rm -f "$f";u=$((u+1));};fi;done< <(find "$p" \( -type f -o -type d \));done< <(grep 'block_ad' "$AGH_DIR/scripts/NoAdsService.sh"|grep -o '".*"'|tr -d '"')
    i18n_print "- Removed $u locked files out of $c scanned items" "- 从 $c 个文件中删除了 $u 个锁定文件"
}

# 直接替代：不再備份/保留舊配置（用戶只用自有 root 版，不裝他人版本）。
# 順帶清理歷史殘留的備份目錄（舊邏輯備份的是 bin/AdGuardHome.yaml 而非實際讀取的
# bin/data/AdGuardHome.yaml，本就無效）。
rm -rf "$BACKUP_DIR"

# 解锁脚本防篡改保护
if [ -d "$SCRIPT_DIR" ]; then
    i18n_print "- Unlocking old script files" "- 正在解锁旧脚本文件"
    find "$AGH_DIR/scripts" "$ADGPATH" -type f -name "*.sh" -exec chattr -i {} \;
fi

# 清除旧模块残留
if [ -d "$AGH_DIR/ifw" ] || [ -d "$AGH_DIR/scripts" ] || [ -d "$BIN_DIR/agh_pid" ] || [ -d "$BIN_DIR/data/filters" ]; then
  i18n_print "- Cleaning up old module residues" "- 正在清理旧模块残留"
  rm -rf "$AGH_DIR/ifw" "$AGH_DIR/scripts" "$BIN_DIR/agh_pid" "$BIN_DIR/data/filters"
fi

# 创建目录并解压文件
mkdir -p "$AGH_DIR" "$BIN_DIR" "$SCRIPT_DIR" "$BACKUP_DIR"
i18n_print "- Extracting AdGuardHome files" "- 正在解压 AdGuardHome 文件"
unzip -o "$ZIPFILE" "scripts/*" -d "$AGH_DIR"
unzip -o "$ZIPFILE" "bin/*" -d "$AGH_DIR"
i18n_print "- Setting permissions" "- 设置权限"
find "$AGH_DIR" -type d -exec chmod 0700 {} \;
chmod +x "$BIN_DIR/AdGuardHome" 
chmod +x "$SCRIPT_DIR"/*.sh
chown root:net_raw "$BIN_DIR/AdGuardHome"

# 不再给脚本加 chattr +i 防篡改锁：
# 1) 它挡不住任何有 root 的人（一条 chattr -i 就开），只是给后续维护/修复添堵；
# 2) 手机上直接改配置（端口、启动参数）时会写出 Permission denied 假象，排查成本极高。
# 安装时仍保留上面对旧安装的解锁步骤，确保从历史版本升级能覆盖。

# 配置直接採用模組內建版本（bin/data/AdGuardHome.yaml、config.prop），不再從備份還原。
i18n_print "- Installation complete. Reboot device." "- 安装完成，请重启设备。"