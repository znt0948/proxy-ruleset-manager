# proxy-ruleset-manager

一个用于整理代理规则集的生成工具。项目从 `source/*.yaml` 读取上游规则，生成 sing-box、Surge、Shadowrocket、Clash/Mihomo 等格式的规则文件，并通过 GitHub Actions 定时更新。

## 功能

- 从 YAML、LIST、JSON、SRS、AdGuard 等来源拉取规则
- 合并、去重并按 `domain_suffix` 清理重复域名
- 生成 sing-box JSON/SRS 规则集
- 转换 Surge、Shadowrocket、Clash YAML 和 Mihomo MRS 规则集
- 生成 sing-box route 配置片段
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

生成结果会写入：

- `rule/singbox/`
- `rule/surge/`
- `rule/shadowrocket/`
- `rule/clash/`
- `src/config/singbox/sb_route.json`
- `template/singbox/config.json`

## 添加规则源

在 `source/` 下新增或修改 YAML 文件：

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
