# proxy-ruleset-manager

一个用于整理代理规则集的生成工具。项目从 `upstream/*.yaml` 读取上游规则，生成 sing-box、Surge、Shadowrocket、Clash/Mihomo 等格式的规则文件，并通过 GitHub Actions 定时更新。

## 功能

- 从 YAML、LIST、JSON、SRS、AdGuard 等来源拉取规则
- 合并、去重并按 `domain_suffix` 清理重复域名
- 生成 sing-box JSON/SRS 规则集
- 转换 Surge、Shadowrocket、Clash YAML 和 Mihomo MRS 规则集
- 支持 `blacklist/` 同名文件对生成结果做排除修正

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
blacklist/            # 生成后排除规则
rule/                 # 自动生成的规则产物
```
