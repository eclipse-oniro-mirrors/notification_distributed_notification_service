#!/bin/bash
# ============================================================================
# run_acts.sh - ACTS 链路：编译(子系统级) -> 推送套件 -> 板上执行 -> 回收报告
# 用法: run_acts.sh <part> [module]
#   part    部件名（如 hitrace）
#   module  ACTS 模块名（如 ActsHitraceMeterTest）；省略则跑该部件全部模块
# 示例: run_acts.sh hitrace ActsHitraceMeterTest
# 关键点(详见 SKILL.md):
#   - --gn-args build_xts=true（--build-xts 只作用 loader 阶段，无效！）
#   - XTS_SUITENAME=acts + target_subsystem=<acts目录名> 环境变量
#   - 产品配置临时注入 xts/acts 子系统（不能带 tools），编完还原
#   - deploy_testtools 需单独编（套件的 run.bat/xdevice 轮子）
# ============================================================================
source "$(dirname "$0")/common.sh"
[ $# -lt 1 ] && { echo "用法: $0 <part> [module]  例: $0 hitrace ActsHitraceMeterTest"; exit 1; }
require_config || exit 1
cd "$CODE_DIR" || exit 1
PART="$1"; MODULE="${2:-}"

# ---------- 前置检查 ----------
check_tunnel || exit 1
check_board || exit 1

# ---------- 部件 -> 构建目标/子系统 ----------
acts_buildtarget_of() {
    python3 - "$1" <<'EOF'
import json, sys
part = sys.argv[1]
for it in json.load(open('test/xts/tools/config/precise_compilation.json')):
    if it['name'].endswith('_' + part) or it['name'] == part:
        print(it['buildTarget']); break
EOF
}
acts_subsystem_of() {
    grep -rl "group(\"$1\")" test/xts/acts/ --include=BUILD.gn 2>/dev/null | head -1 | sed 's|test/xts/acts/||;s|/BUILD.gn||'
}
BT=$(acts_buildtarget_of "$PART")
[ -z "$BT" ] && { echo "[ERROR] precise_compilation.json 中找不到部件 $PART 的 ACTS 构建目标"; exit 1; }
SUBSYS=$(acts_subsystem_of "$BT"); [ -z "$SUBSYS" ] && SUBSYS="$PART"
echo "[ACTS] $PART -> buildTarget=$BT, target_subsystem=$SUBSYS"

# ---------- 产品配置定位与补丁 ----------
PRODUCT_CONFIG=$(find vendor -maxdepth 3 -path "*/$PRODUCT_NAME/*" -name config.json 2>/dev/null | head -1)
[ -z "$PRODUCT_CONFIG" ] && { echo "[ERROR] 未找到 $PRODUCT_NAME 的产品配置(vendor/*/$PRODUCT_NAME/config.json)"; exit 1; }
echo "[ACTS] 产品配置: $PRODUCT_CONFIG"
acts_patch_config() {
    python3 -c "
import json; p='$PRODUCT_CONFIG'
cfg=json.load(open(p))
if not any(s['subsystem']=='xts' for s in cfg['subsystems']):
    cfg['subsystems'].append({'subsystem':'xts','components':[{'component':'acts','features':[]}]})
    json.dump(cfg,open(p,'w'),indent=2,ensure_ascii=False)
" || { echo "[ERROR] 产品配置打补丁失败"; return 1; }
    echo "[ACTS] 产品配置已注入 xts/acts 子系统"
}
acts_restore_config() {
    python3 -c "
import json; p='$PRODUCT_CONFIG'
cfg=json.load(open(p))
cfg['subsystems']=[s for s in cfg['subsystems'] if s['subsystem']!='xts']
json.dump(cfg,open(p,'w'),indent=2,ensure_ascii=False)
" && echo "[ACTS] 产品配置已还原(移除 xts)"
}

# ---------- 编译 ----------
acts_patch_config || exit 1
rc=0
for tgt in "$BT" "test/xts/acts/testtools:deploy_testtools"; do
    echo "[BUILD] ACTS $tgt ..."
    XTS_SUITENAME=acts target_subsystem="$SUBSYS" \
        ./build.sh --product-name "$PRODUCT_NAME" --gn-args build_xts=true --build-target "$tgt" \
        > "$LOG_DIR/acts_build.log" 2>&1 || { tail -15 "$LOG_DIR/acts_build.log"; rc=1; break; }
done
acts_restore_config
[ $rc -ne 0 ] && exit 1
NHAP=$(ls out/$PRODUCT_NAME/suites/acts/acts/testcases/*.hap 2>/dev/null | wc -l)
[ "$NHAP" -eq 0 ] && { echo "[ERROR] 套件无 hap 产物"; exit 1; }
echo "      套件就绪: out/$PRODUCT_NAME/suites/acts/acts ($NHAP 个 hap)"

# ---------- 推送套件 ----------
echo "[PUSH] ACTS 套件推送 ..."
tar czf "$LOG_DIR/acts_suite.tar.gz" -C out/$PRODUCT_NAME/suites/acts/acts . || exit 1
win_ssh "(if not exist $WIN_DIR_BS\\tmp mkdir $WIN_DIR_BS\\tmp)" || exit 1
$SCP_CMD "$LOG_DIR/acts_suite.tar.gz" "$WIN_USER@127.0.0.1:$WIN_TMP/" || exit 1
win_ssh "cd /d $WIN_DIR_BS && (if not exist acts mkdir acts) && cd acts && tar xzf ..\\tmp\\acts_suite.tar.gz && del ..\\tmp\\acts_suite.tar.gz" || exit 1
# 首次安装 xdevice 轮子(幂等)
win_ssh "\"$PYTHON_EXE\" -c \"import ohos\" 2>nul || \"$PYTHON_EXE\" -m pip install --user --quiet $WIN_DIR_BS\\acts\\tools\\xdevice-0.0.0.tar.gz $WIN_DIR_BS\\acts\\tools\\xdevice_ohos-0.0.0.tar.gz $WIN_DIR_BS\\acts\\tools\\xdevice_devicetest-0.0.0.tar.gz" || exit 1

# ---------- 远程执行 ----------
ARGS="run acts"
[ -n "$MODULE" ] && ARGS="run acts -l $MODULE"
echo "[RUN] 远程执行 ACTS: $ARGS"
win_ssh "set PATH=$TOOLCHAINS_DIR;%PATH% && cd /d $WIN_DIR_BS\\acts && \"$PYTHON_EXE\" -m xdevice $ARGS" 2>&1 | tail -12

# ---------- 回收报告 ----------
collect_report acts
