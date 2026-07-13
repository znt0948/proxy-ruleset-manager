# proxy-ruleset-manager

一个用于整理代理规则集的生成工具。项目从 `upstream/*.yaml` 读取上游规则，生成 sing-box、Surge、Shadowrocket、Clash/Mihomo 等格式的规则文件，并通过 GitHub Actions 定时更新。

本项目只负责规则集的获取、清洗、合并、优化与格式转换，不生成或修改 sing-box、Mihomo 等客户端的运行配置。

## 功能

- 从 YAML、LIST、JSON、SRS、AdGuard 等来源拉取规则
- 合并、去重并按 `domain_suffix` 清理重复域名
- 所有 `domain_suffix` 统一为“根域名 + 全部子域名”语义：输入的 `example.com`、`.example.com`、`+.example.com` 均规范化为 `example.com`；Mihomo domain provider 输出为 `+.example.com`
- `domain`、`domain_suffix`、`domain_keyword` 统一转为小写；`domain_regex`、进程名和进程路径保持原样，避免改变正则或文件系统匹配语义
- Unicode 域名规范化为 IDNA/Punycode；误放在域名字段中的 IP/CIDR 自动迁移到 `ip_cidr`；URL、路径和带端口域名视为无效输入
- 拒绝把 `*.example.com` 当作 suffix，因为它不包含根域名，语义不同
- 分类修正在 suffix/CIDR 覆盖去重之前执行，避免错误父规则被修正后，正确的子规则已经提前丢失
- sing-box 输出会把 `domain`、`domain_suffix`、`domain_keyword`、`domain_regex` 安全打包到一个目标域名规则中，减少顶层规则遍历；其他字段保持独立
- 生成 sing-box JSON/SRS 规则集
- 转换 Surge、Shadowrocket、Clash YAML 和 Mihomo MRS 规则集
- 支持 `corrections/` 同名文件修正上游的错误分类
- 对每个结构化上游分别清洗后再合并，并生成 `report/ruleset-quality.json`，记录单上游去重、合并后去重和精确来源重叠；`domain_keyword` 仅做规范化与完全重复去重，不参与覆盖推断

规则处理顺序固定为：

```text
解析 → 字段规范化 → 完全重复去重 → 分类修正
     → suffix/CIDR 覆盖去重 → 按引擎组织规则 → 编译验证
```

## 环境要求

- Python 3.10+
- `sing-box`
- `mihomo`

安装 Python 依赖：

```bash
pip install -r requirements.txt
```

如果使用 conda：

```bash
conda activate proxy-ruleset-manager
pip install -r requirements.txt
```

## 使用

```bash
python main.py
```

`main.py` 是兼容旧用法的薄入口，实际代码位于 `src/proxy_ruleset_manager/` 包内。

生成结果会写入：

- `rule/singbox/`
- `rule/surge/`
- `rule/shadowrocket/`
- `rule/clash/`

## 添加规则源

在 `upstream/` 下新增或修改 YAML 文件：

```yaml
geosite:
  - "https://example.com/rules.yaml"
geoip:
  - "https://example.com/ip-rules.yaml"
process:
  - "https://example.com/process.json"
```

文件名会参与生成规则集名称，例如 `category-direct.yaml` 会生成 `geosite-category-direct.*` 或 `geoip-category-direct.*`。

## 自动更新

`.github/workflows/sync.yml` 会在 `main` 分支 push、手动触发、以及每天定时运行时重新生成规则并提交变更。

## 项目结构

```text
src/
  proxy_ruleset_manager/
    cli.py            # 命令入口
    config.py         # 配置和日志初始化
    pipeline.py       # 规则生成主流程
    fetchers.py       # 下载和外部命令辅助出口
    parsers.py        # 规则源解析辅助出口
    normalizers.py    # 规则清洗/标准化辅助出口
    rules.py          # 规则合并、去重和读写辅助出口
    converters/       # 各客户端格式转换出口
upstream/             # 上游规则源定义
self-host/            # 仓库自维护规则源
corrections/          # 按输出文件名修正上游错误分类
report/               # 规则质量、来源重叠和发布产物统计
rule/                 # 自动生成的规则产物
```
