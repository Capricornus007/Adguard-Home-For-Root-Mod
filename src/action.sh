#!/system/bin/sh
AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
# 實際生效的配置是 bin/data/AdGuardHome.yaml（service.sh 以 bin/data 為 cwd）；
# 讀 bin/AdGuardHome.yaml 會拿到一份沒人用的舊檔，端口因此取錯。
YAML_FILE="$BIN_DIR/data/AdGuardHome.yaml"

echo "等待 1 秒..."
echo "刷新页面以查看更改。"
sleep 1

# 获取动态端口
PORT=$(sed -n 's/^[[:space:]]*address: 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$YAML_FILE")

# 自动跳转到浏览器并打开 Web UI
echo "正在打开浏览器 (端口 $PORT)..."
am start -a android.intent.action.VIEW -d "http://127.0.0.1:$PORT"