# utils.py

import requests
import json
import re
import ipaddress
import pandas as pd
import yaml
import logging
import os
import subprocess

from .config import Config

config = Config()

RULE_VALUE_FIELDS = (
    "query_type",
    "network",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_ip_cidr",
    "ip_cidr",
    "geoip",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "package_name_regex",
    "network_type",
    "network_interface_address",
    "default_interface_address",
    "wifi_ssid",
    "wifi_bssid",
)

LOGICAL_RULE_KEYS = {"type", "mode", "rules"}
CLASH_CLASSICAL_ONLY_FIELDS = {
    "domain_keyword",
    "domain_regex",
    "source_ip_cidr",
    "geoip",
    "port",
    "source_port",
    "process_name",
}


def run_command(command, description):
    """Run an external command and raise with useful logs on failure."""
    logging.debug(f"{description}: {' '.join(command)}")
    try:
        return subprocess.run(command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"{description}失败，错误码 {e.returncode}")
        if e.stderr:
            logging.error(e.stderr.strip())
        raise


def merge_rules(existing_data, new_data):
    """
    合并两个规则集，不进行去重。
    如果传入的数据是列表，则直接合并。
    如果传入的数据是字典，按字段进行合并。
    """
    # 如果输入数据是列表，直接合并
    if isinstance(existing_data, list) and isinstance(new_data, list):
        return existing_data + new_data

    # 否则，按字段进行合并
    merged_data = {}
    for field in RULE_VALUE_FIELDS:
        values = []
        if isinstance(existing_data, dict):
            existing_values = existing_data.get(field, [])
            values.extend(existing_values if isinstance(existing_values, list) else [existing_values])
        if isinstance(new_data, dict):
            new_values = new_data.get(field, [])
            values.extend(new_values if isinstance(new_values, list) else [new_values])
        if values:
            merged_data[field] = values
    return merged_data


def read_yaml_from_url(url):
    response = requests.get(url, timeout=config.request_timeout)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    # logging.info(f"成功读取 YAML 数据 {url}")
    return yaml_data


def read_list_from_url(url):
    try:
        df = pd.read_csv(url, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'])
        # logging.info(f"成功读取列表数据 {url}")
    except Exception as e:
        logging.error(f"读取 {url} 时出错：{e}")
        return pd.DataFrame(), []

    filtered_rows = []
    rules = []

    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {"type": "logical", "mode": "and", "rules": []}
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in config.map_dict.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({config.map_dict[keyword]: value})
            rules.append(rule)
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules


def normalize_payload_items(yaml_data):
    if isinstance(yaml_data, dict):
        items = yaml_data.get('payload', [])
    elif isinstance(yaml_data, list):
        items = yaml_data
    elif isinstance(yaml_data, str):
        items = yaml_data.splitlines()
    else:
        items = []

    normalized = []
    for item in items:
        value = str(item).strip()
        if not value or value.startswith('#'):
            continue
        if value.startswith('- '):
            value = value[2:].strip()
        if ' #' in value:
            value = value.split(' #', 1)[0].strip()
        value = value.strip("'\"")
        if value:
            normalized.append(value)
    return normalized


def normalize_adguard_rule_line(line):
    value = line.strip()
    if not value:
        return None
    if value.startswith("!") or value.startswith("["):
        return None

    hosts_rule = normalize_adguard_hosts_line(value)
    if hosts_rule is not None:
        return hosts_rule

    if not is_supported_adguard_modifier_rule(value):
        return None

    return value


def normalize_adguard_hosts_line(value):
    parts = value.split()
    if len(parts) < 2:
        return None

    ip_value = parts[0]
    if ip_value == "0.0.0.0":
        return " ".join(parts[:2])

    try:
        ipaddress.ip_address(ip_value)
    except ValueError:
        return None

    logging.debug(f"跳过 sing-box 不支持的 AdGuard hosts 行: {value}")
    return ""


def is_supported_adguard_modifier_rule(value):
    if "$" not in value:
        return True

    modifiers_part = value.rsplit("$", 1)[1]
    modifiers = [modifier.strip().lower() for modifier in modifiers_part.split(",") if modifier.strip()]
    if not modifiers:
        return True

    supported_modifiers = {"important", "dnsrewrite=0.0.0.0"}
    unsupported_modifiers = [modifier for modifier in modifiers if modifier not in supported_modifiers]
    if unsupported_modifiers:
        logging.debug(f"跳过 sing-box 不支持的 AdGuard modifier 规则: {value}")
        return False

    return True


def deduplicate_adguard_lines(lines):
    seen = set()
    deduplicated = []

    for line in lines:
        value = normalize_adguard_rule_line(line)
        if not value or value in seen:
            continue
        deduplicated.append(value)
        seen.add(value)

    return deduplicated


def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None


def clean_json_data(data):
    """清洗 JSON 数据，移除末尾多余的逗号。"""
    cleaned_data = re.sub(r',\s*]', ']', data)  # 处理数组末尾的逗号
    cleaned_data = re.sub(r',\s*}', '}', cleaned_data)  # 处理对象末尾的逗号
    return cleaned_data


def clean_denied_domains(domains):
    """清洗 denied-remote-domains 列表中的域名并分类。"""
    cleaned_domains = {
        "domain": [],
        "domain_suffix": []
    }

    for domain in domains:
        domain = domain.strip()  # 去除前后空格
        if domain:  # 确保域名不为空
            parts = domain.split('.')
            # 判断是否为没有子域名的域名
            if len(parts) == 2:  # 例如 "0512s.com"
                cleaned_domains["domain"].append(domain)
                cleaned_domains["domain_suffix"].append("." + domain)  # 将带点的形式添加到 domain_suffix
            elif len(parts) > 2:  # 例如 "counter.packa2.cz"
                cleaned_domains["domain"].append(domain)

    return cleaned_domains


def parse_and_convert_to_dataframe(link):
    rules = []
    try:
        if link.endswith('.yaml') or link.endswith('.txt'):
            yaml_data = read_yaml_from_url(link)
            rows = []
            items = normalize_payload_items(yaml_data)
            for item in items:
                address = item.strip("'\"")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                if pattern == "IP-CIDR" and "no-resolve" in address:
                    address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        else:
            df, rules = read_list_from_url(link)
    except Exception as e:
        logging.error(f"解析 {link} 时出错：{e}")
        return pd.DataFrame(), []

    # logging.info(f"成功解析链接 {link}")
    return df, rules


def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj


def make_hashable(item):
    """递归地将可变类型（如列表）转换为元组，以便它们可以添加到集合中"""
    if isinstance(item, dict):
        # 如果是字典，将其转换为元组
        return tuple((key, make_hashable(value)) for key, value in item.items())
    elif isinstance(item, list):
        # 如果是列表，将每个元素递归转换为元组
        return tuple(make_hashable(i) for i in item)
    else:
        # 如果是其他不可变类型，直接返回
        return item


def subtract_rules(base_data, subtract_data):
    """Return base_data minus subtract_data, including suffix coverage."""

    subtract_values = {field: set() for field in RULE_VALUE_FIELDS}

    for rule in subtract_data:
        if not isinstance(rule, dict):
            continue
        for key in subtract_values:
            values = rule.get(key, [])
            if isinstance(values, list):
                subtract_values[key].update(values)
            elif isinstance(values, str):
                subtract_values[key].add(values)

    deduplicated_data = deduplicate_json(base_data)
    subtract_suffixes = {value.strip().lstrip(".") for value in subtract_values["domain_suffix"]}
    suffix_trie = build_suffix_trie(subtract_suffixes)
    subtract_domains = {value.strip().lstrip(".") for value in subtract_values["domain"]}

    for item in deduplicated_data:
        if not isinstance(item, dict):
            continue

        for key, values in list(item.items()):
            if key not in subtract_values or not isinstance(values, list):
                continue

            if key == "domain":
                item[key] = [
                    val for val in values
                    if val.strip().lstrip(".") not in subtract_domains
                    and not suffix_trie.has_suffix(val.strip().lstrip("."))
                ]
            elif key == "domain_suffix":
                item[key] = [
                    val for val in values
                    if val.strip().lstrip(".") not in subtract_domains
                    and val.strip().lstrip(".") not in subtract_suffixes
                    and not suffix_trie.has_suffix(val.strip().lstrip("."))
                ]
            elif subtract_values[key]:
                item[key] = [val for val in values if val not in subtract_values[key]]

    return prune_empty_rules(deduplicated_data)


def load_json(filepath):
    """加载 JSON 文件"""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, filepath):
    """保存 JSON 文件"""
    try:
        # 假设 data 已经是一个包含规则的列表，如：{"domain": [...]}, {"ip_cidr": [...]}, ...
        result = {
            "version": 1,
            "rules": data
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
    except Exception as e:
        logging.error(f"保存 JSON 文件时出错: {e}")


def deduplicate_json(data):
    """
    对输入的 JSON 数据进行三轮去重操作：
    1. 第一轮去重：检查 process_name, domain, domain_suffix, ip_cidr, domain_regex 中是否有完全一致的条目。
    2. 第二轮去重：使用 domain_regex 清洗 domain 和 domain_suffix。
    3. 第三轮去重：使用 domain_suffix 去重 domain，基于 Trie 进行去重。
    """

    # 第一轮去重：初始化合并规则
    merged_rules = {field: set() for field in RULE_VALUE_FIELDS}
    logical_rules = []
    seen_logical_rules = set()

    # 遍历输入列表，逐一合并规则
    for rule in data:
        if isinstance(rule, dict):  # 确保条目是字典
            if LOGICAL_RULE_KEYS.issubset(rule.keys()):
                marker = make_hashable(rule)
                if marker not in seen_logical_rules:
                    logical_rules.append(rule)
                    seen_logical_rules.add(marker)
                continue
            for category, values in rule.items():
                if category in merged_rules:
                    if isinstance(values, list):
                        merged_rules[category].update(values)
                    elif isinstance(values, str):
                        merged_rules[category].add(values)

    # 第二轮去重：使用 domain_regex 清洗 domain 和 domain_suffix
    final_domains = merged_rules["domain"].copy()
    domain_suffix = merged_rules["domain_suffix"]
    domain_regex = merged_rules["domain_regex"]

    compiled_regexes = compile_domain_regexes(domain_regex)

    # 用 domain_regex 去重 domain 和 domain_suffix
    if compiled_regexes:
        # 清洗 domain
        for regex in compiled_regexes:
            final_domains = {domain for domain in final_domains if not regex.search(domain)}

        # 清洗 domain_suffix
        for regex in compiled_regexes:
            domain_suffix = {suffix for suffix in domain_suffix if not regex.fullmatch(suffix)}

    merged_rules["domain"] = final_domains
    merged_rules["domain_suffix"] = domain_suffix

    # 第三轮去重：使用 Trie 对 domain_suffix 自身去重，并清洗 domain
    merged_rules["domain_suffix"] = filter_domain_suffixes_with_trie(merged_rules["domain_suffix"])
    final_domains, _ = filter_domains_with_trie(merged_rules["domain"], merged_rules["domain_suffix"])
    merged_rules["domain"] = final_domains

    merged_rules["ip_cidr"] = collapse_cidr_values(merged_rules["ip_cidr"], "ip_cidr")
    merged_rules["source_ip_cidr"] = collapse_cidr_values(merged_rules["source_ip_cidr"], "source_ip_cidr")

    # 构造最终的输出列表
    final_rules = []
    for category, values in merged_rules.items():
        if values:
            final_rules.append({category: sorted(values)})

    return logical_rules + final_rules


def prune_empty_rules(rules):
    pruned_rules = []
    for rule in rules:
        if not isinstance(rule, dict):
            pruned_rules.append(rule)
            continue
        if LOGICAL_RULE_KEYS.issubset(rule.keys()):
            pruned_rules.append(rule)
            continue

        pruned_rule = {
            key: value
            for key, value in rule.items()
            if not isinstance(value, list) or value
        }
        if pruned_rule:
            pruned_rules.append(pruned_rule)
    return pruned_rules


def convert_sets_to_lists(data):
    """递归地将字典中的所有 set 转换为 list"""
    if isinstance(data, dict):
        return {key: convert_sets_to_lists(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_sets_to_lists(item) for item in data]
    elif isinstance(data, set):
        return list(data)
    else:
        return data


def match_domain_regex(domain, regex):
    """
    根据 domain 和 domain_regex 判断是否匹配
    假设这里是简单的正则匹配，你可以根据实际情况调整
    """
    return bool(re.search(regex, domain))


def match_domain_suffix_regex(suffix, regex):
    """
    用于匹配 domain_suffix 的正则表达式，确保是匹配后缀
    """
    return bool(re.match(f"^{regex}$", suffix))


def compile_domain_regexes(regexes):
    compiled_regexes = []
    for regex in regexes:
        try:
            compiled_regexes.append(re.compile(regex))
        except re.error as e:
            logging.warning(f"跳过无效 domain_regex: {regex}, 错误: {e}")
    return compiled_regexes


def collapse_cidr_values(values, field_name):
    ipv4_networks = []
    ipv6_networks = []
    invalid_values = set()

    for value in values:
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            invalid_values.add(value)
            logging.warning(f"跳过无效 {field_name}: {value}")
            continue

        if isinstance(network, ipaddress.IPv4Network):
            ipv4_networks.append(network)
        else:
            ipv6_networks.append(network)

    collapsed = set()
    collapsed.update(str(network) for network in ipaddress.collapse_addresses(ipv4_networks))
    collapsed.update(str(network) for network in ipaddress.collapse_addresses(ipv6_networks))
    collapsed.update(invalid_values)
    return collapsed


# json去重算法
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, suffix):
        """ 插入 domain_suffix，确保不包含前导 . """
        suffix = suffix.lstrip('.')
        node = self.root
        for char in reversed(suffix):  # 倒序插入，方便匹配后缀
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end = True

    def has_suffix(self, domain):
        """ 检查 domain 是否匹配某个完整的 domain_suffix """
        node = self.root
        domain = '.' + domain  # 加入前导点进行后缀匹配

        # 从尾部倒序遍历 domain
        for i in range(len(domain)):
            char = domain[-(i + 1)]
            if node.is_end and i != 0:  # 如果已经匹配到后缀，且 i != 0，代表匹配到完整后缀
                # 确保匹配的后缀是完整的二级域名
                if i == len(domain) - 1:  # 完全匹配
                    return True
                elif domain[-(i + 1)] == '.':  # 确保后缀结束在域名边界
                    return True
                else:
                    return False  # 如果有更多字符，且未结束，说明匹配是部分的
            if char not in node.children:
                return False
            node = node.children[char]

        # 完全匹配一个后缀时，结束条件
        return node.is_end


def filter_domains_with_trie(domains, domain_suffixes):
    trie = build_suffix_trie(domain_suffixes)

    filtered_domains = set()
    filtered_count = 0

    # 预处理：把所有后缀规范化为不含前导点的形式，放在集合里（便于快速比对）
    clean_suffixes = {s.lstrip('.') for s in domain_suffixes}

    for domain in domains:
        if trie.has_suffix(domain):
            # 如果 domain 恰好等于某个后缀（根域名），则保留
            if domain in clean_suffixes:
                filtered_domains.add(domain)
            else:
                filtered_count += 1
        else:
            filtered_domains.add(domain)

    return filtered_domains, filtered_count


def build_suffix_trie(domain_suffixes):
    trie = Trie()
    for suffix in domain_suffixes:
        if suffix:
            trie.insert(suffix)
    return trie


def filter_domain_suffixes_with_trie(domain_suffixes):
    trie = Trie()
    filtered_suffixes = set()
    clean_suffixes = {suffix.strip().lstrip(".") for suffix in domain_suffixes if suffix}

    for suffix in sorted(clean_suffixes, key=lambda value: (value.count("."), len(value), value)):
        if not trie.has_suffix(suffix):
            trie.insert(suffix)
            filtered_suffixes.add(suffix)

    return filtered_suffixes

def convert_json_to_surge(input_dir):
    """
    读取指定目录下的所有 JSON 文件，将其转换为 Surge 和 Shadowrocket 规则，并存储在 config 指定的目录下。
    """
    surge_output_dir = config.surge_output_directory
    shadowrocket_output_dir = config.shadowrocket_output_directory

    os.makedirs(surge_output_dir, exist_ok=True)
    os.makedirs(shadowrocket_output_dir, exist_ok=True)

    for filename in sorted(os.listdir(input_dir)):
        if filename.endswith(".json"):
            input_path = os.path.join(input_dir, filename)
            surge_output_path = os.path.join(surge_output_dir, filename.replace(".json", ".list"))
            shadowrocket_output_path = os.path.join(shadowrocket_output_dir, filename.replace(".json", ".list"))

            try:
                with open(input_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # 计算一次 `surge_rules`
                surge_rules = []
                for rule in data.get("rules", []):
                    for rule_type, values in rule.items():
                        if rule_type in config.SINGBOX_TO_SURGE_MAP:
                            surge_type = config.SINGBOX_TO_SURGE_MAP[rule_type]
                            for value in values:
                                surge_rules.append(f"{surge_type},{value}")

                # 将规则写入 Surge 和 Shadowrocket 文件
                with open(surge_output_path, "w", encoding="utf-8") as f1, \
                        open(shadowrocket_output_path, "w", encoding="utf-8") as f2:
                    # 直接写入每个规则
                    for rule in sorted(surge_rules):
                        f1.write(f"{rule}\n")
                        f2.write(f"{rule}\n")

                logging.info(f"转换完成: {input_path} → {surge_output_path}, {shadowrocket_output_path}")

            except Exception as e:
                logging.error(f"转换 {input_path} 时出错: {e}")


def convert_adguard_to_surge(input_path, rule_set_name):
    """
    读取 AdGuard 规则文件，并转换为 Surge/Shadowrocket 规则。
    结果分别存储在 `config.surge_output_dir` 和 `config.shadowrocket_output_dir` 目录下。
    """
    if not os.path.exists(input_path):
        logging.error(f"文件不存在: {input_path}")
        return

    # 固定输出目录
    surge_output_dir = config.surge_output_directory
    shadowrocket_output_dir = config.shadowrocket_output_directory

    os.makedirs(surge_output_dir, exist_ok=True)
    os.makedirs(shadowrocket_output_dir, exist_ok=True)

    # 生成输出文件名
    output_filename = f"{rule_set_name}.list"
    surge_output_path = os.path.join(surge_output_dir, output_filename)
    shadowrocket_output_path = os.path.join(shadowrocket_output_dir, output_filename)

    surge_rules = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("["):  # 忽略注释和无效行
                continue

            # 处理 DOMAIN-SUFFIX 规则 (||example.com^)
            if line.startswith("||"):
                domain = line[2:].split("^")[0]
                surge_rules.append(f"DOMAIN-SUFFIX,{domain}")
            # 处理 DOMAIN 规则 (example.com^)
            elif line.endswith("^") and not line.startswith("|") and not line.startswith("@@"):
                domain = line[:-1]
                surge_rules.append(f"DOMAIN,{domain}")
            # 处理 DOMAIN 规则 (|example.com)
            elif line.startswith("|") and "/" not in line:
                domain = line[1:]
                surge_rules.append(f"DOMAIN,{domain}")

            # 处理 URL 规则 (|http://example.com/ads.js)
            elif line.startswith("|http"):
                url = line[1:].replace(".", r"\.")  # 转义 .
                surge_rules.append(f"URL-REGEX,^{url}$")

            # 处理 URL 正则匹配规则 (/ads\.(js|php)/)
            elif line.startswith("/") and line.endswith("/"):
                regex = line[1:-1]  # 去掉前后的 /
                surge_rules.append(f"URL-REGEX,{regex}")

            # 处理 IP-CIDR 规则 (127.0.0.1)
            elif re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                surge_rules.append(f"IP-CIDR,{line}/32")

            # 处理允许（白名单）规则 (@@||example.com^)
            elif line.startswith("@@||"):
                domain = line[4:].split("^")[0]
                surge_rules.append(f"DOMAIN-SUFFIX,{domain},DIRECT")

            # 其他规则忽略
            else:
                logging.warning(f"未识别的 AdGuard 规则: {line}")

    # **写入 Surge & Shadowrocket 规则文件**
    rule_text = "\n".join(surge_rules)
    with open(surge_output_path, "w", encoding="utf-8") as f1, \
            open(shadowrocket_output_path, "w", encoding="utf-8") as f2:
        f1.write(rule_text)
        f2.write(rule_text)

    logging.info(f"AdGuard 规则转换完成: {input_path} → {surge_output_path}, {shadowrocket_output_path}")


def clean_comment(value):
    """ 去除值中的注释（# 之后的内容）"""
    return value.split("#")[0].strip()


def fix_domain_prefix(value):
    """ 如果是 DOMAIN 相关类型，去除开头的 `.` """
    return value.lstrip(".") if value.startswith(".") else value


def clash_rule_provider_behavior(data, filename):
    if filename.startswith("geoip"):
        default_behavior = "ipcidr"
    elif filename.startswith("geosite"):
        default_behavior = "domain"
    else:
        default_behavior = "classical"

    for rule in data.get("rules", []):
        if not isinstance(rule, dict):
            continue
        if LOGICAL_RULE_KEYS.issubset(rule.keys()):
            return "classical"
        if any(field in rule for field in CLASH_CLASSICAL_ONLY_FIELDS):
            return "classical"
    return default_behavior


def clash_classical_rule(clash_type, value):
    return f"{clash_type},{value}"


def clash_domain_rule(clash_type, value):
    if clash_type == "DOMAIN-SUFFIX":
        if value.startswith('+') or value.startswith('*.'):
            return value
        return f"+.{value.lstrip('.')}"
    return value


def render_clash_logical_rule(rule):
    rendered_children = []
    for child in rule.get("rules", []):
        if not isinstance(child, dict):
            continue
        for rule_type, value in child.items():
            if rule_type not in config.SINGBOX_TO_CLASH_MAP:
                continue
            clash_type = config.SINGBOX_TO_CLASH_MAP[rule_type]
            rendered_children.append(clash_classical_rule(clash_type, clean_comment(str(value))))

    if not rendered_children:
        return None

    mode = str(rule.get("mode", "and")).upper()
    return f"{mode},({','.join(rendered_children)})"


def convert_json_to_clash(input_dir):
    """
    读取指定目录下的所有 JSON 规则文件，并将其转换为 Clash 规则格式。
    如果文件中没有有效规则（全部被跳过），则不生成对应的 YAML 文件。
    """
    output_dir = config.clash_output_directory
    os.makedirs(output_dir, exist_ok=True)

    for filename in sorted(os.listdir(input_dir)):
        if filename.endswith(".json"):
            input_path = os.path.join(input_dir, filename)
            output_path = os.path.join(output_dir, filename.replace(".json", ".yaml"))

            try:
                with open(input_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                behavior = clash_rule_provider_behavior(data, filename)
                clash_rules = []
                for rule in data.get("rules", []):
                    if isinstance(rule, dict) and LOGICAL_RULE_KEYS.issubset(rule.keys()):
                        rendered = render_clash_logical_rule(rule)
                        if rendered:
                            clash_rules.append(rendered)
                        continue

                    for rule_type, values in rule.items():
                        if rule_type in config.SINGBOX_TO_CLASH_MAP:
                            clash_type = config.SINGBOX_TO_CLASH_MAP[rule_type]

                            val_list = values if isinstance(values, list) else [values]
                            for value in val_list:
                                cleaned_value = clean_comment(str(value))

                                if behavior == "classical":
                                    clash_rules.append(clash_classical_rule(clash_type, cleaned_value))

                                elif behavior == "ipcidr" and clash_type == "IP-CIDR":
                                    clash_rules.append(f"'{cleaned_value}'")

                                elif behavior == "domain" and clash_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
                                    domain_rule = clash_domain_rule(clash_type, cleaned_value)
                                    clash_rules.append(f"'{domain_rule}'")

                                else:
                                    continue

                # --- 关键修改点：判断是否有有效规则 ---
                if not clash_rules:
                    logging.info(f"跳过文件 {filename}: 没有有效的转换规则。")
                    continue

                    # 只有 clash_rules 不为空时，才会执行写入操作
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write("payload:\n")
                    for rule in sorted(clash_rules):
                        f.write(f"  - {rule}\n")

                logging.info(f"成功转换: {filename} -> {os.path.basename(output_path)}")

            except Exception as e:
                logging.error(f"转换 {input_path} 到 Clash 规则时出错：{e}")

def convert_yaml_to_mrs(output_directory):
    """
    遍历指定目录下的 YAML 文件：
    - geosite 开头的文件使用 `mihomo convert-ruleset domain yaml`
    - geoip 开头的文件使用 `mihomo convert-ruleset ipcidr yaml`
    生成对应的 .mrs 规则文件
    """
    yaml_files = sorted(f for f in os.listdir(output_directory) if f.endswith('.yaml'))

    for yaml_file in yaml_files:
        yaml_file_path = os.path.join(output_directory, yaml_file)
        mrs_path = yaml_file_path.replace(".yaml", ".mrs")

        try:
            behavior = detect_clash_yaml_behavior(yaml_file_path, yaml_file)
            if behavior == "classical":
                if os.path.exists(mrs_path):
                    os.remove(mrs_path)
                logging.info(f"跳过 MRS 文件 {mrs_path}: classical 规则集无法安全转换。")
                continue
            if behavior:
                command = ["mihomo", "convert-ruleset", behavior, "yaml", yaml_file_path, mrs_path]
            else:
                continue

            run_command(command, f"生成 MRS 文件 {mrs_path}")
            logging.info(f"成功生成 MRS 文件: {mrs_path}")

        except Exception as e:
            logging.error(f"转换 {yaml_file_path} 到 MRS 文件时出错：{e}")


def detect_clash_yaml_behavior(yaml_file_path, yaml_file):
    try:
        with open(yaml_file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        data = {}

    payload = data.get("payload", []) if isinstance(data, dict) else []
    for item in payload:
        value = str(item).strip().strip("'\"")
        if "," in value:
            return "classical"

    if yaml_file.startswith("geosite"):
        return "domain"
    if yaml_file.startswith("geoip"):
        return "ipcidr"
    return None


def convert_adguard_to_clash(input_path, rule_set_name):
    """
    读取 AdGuard 规则文件，并转换为 Clash 规则格式。
    """

    # 固定输出目录
    clash_output_dir = config.clash_output_directory

    os.makedirs(clash_output_dir, exist_ok=True)
    # 生成输出文件名
    output_filename = f"{rule_set_name}.yaml"
    output_path = os.path.join(clash_output_dir, output_filename)

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            adguard_rules = f.readlines()

        clash_rules = []
        for rule in adguard_rules:
            rule = rule.strip()
            if rule.startswith("||"):  # 处理 AdGuard DOMAIN-SUFFIX 规则
                domain = rule[2:].split("^")[0]
                clash_rules.append(f"- DOMAIN-SUFFIX, {domain}")
            elif rule.startswith("|"):  # 处理 AdGuard DOMAIN 规则
                domain = rule[1:].split("^")[0]
                clash_rules.append(f"- DOMAIN, {domain}")
            elif rule.startswith("@@||"):  # 处理 AdGuard 允许规则
                domain = rule[4:].split("^")[0]
                clash_rules.append(f"- DOMAIN, {domain}, REJECT")
            elif rule.startswith("/") and rule.endswith("/"):  # 处理 AdGuard 正则规则
                regex = rule[1:-1]
                clash_rules.append(f"- DOMAIN-REGEX, {regex}")
            elif re.match(r"^\d+\.\d+\.\d+\.\d+", rule):  # 处理 IP 规则
                clash_rules.append(f"- IP-CIDR, {rule}")

        clash_config = {
            "payload": clash_rules
        }

        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False)

    except Exception as e:
        logging.error(f"转换 {input_path} 到 Clash 规则时出错：{e}")
