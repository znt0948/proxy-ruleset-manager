import os
import json
import logging
import time
import yaml
import concurrent.futures
import pandas as pd
import requests
from .config import Config
from collections import defaultdict
import tempfile
import shutil
from .utils import (
    LOGICAL_RULE_KEYS,
    RULE_VALUE_FIELDS,
    clean_denied_domains,
    clean_json_data,
    convert_json_to_clash,
    convert_json_to_surge,
    convert_sets_to_lists,
    convert_yaml_to_mrs,
    deduplicate_adguard_lines,
    deduplicate_json,
    filter_domains_with_trie,
    load_json,
    make_hashable,
    merge_rules,
    parse_and_convert_to_dataframe,
    run_command,
    save_json,
    subtract_rules,
)

config = Config()


class RuleParser:
    def __init__(self):
        self.ls_index = 1

    def parse_adguard_file(self, yaml_file_path, output_directory):
        """
        处理 AdGuard 链接并返回解析后的 JSON 数据。
        """
        try:
            with open(yaml_file_path, 'r') as file:
                data = yaml.safe_load(file)
                logging.debug(f"解析的 YAML 数据: {data}")

            rule_set_name = os.path.basename(yaml_file_path).split('.')[0]
            adg_links = data.get('adguard', [])
            raw_lines = []

            # 遍历每个 AdGuard 规则文件链接，获取并处理数据
            for link in adg_links:
                try:
                    response = requests.get(link, timeout=config.request_timeout)
                    response.raise_for_status()
                    raw_data = response.text

                    # 将数据按行分割，并添加到集合中去重
                    raw_lines.extend(raw_data.splitlines())

                except requests.RequestException as e:
                    logging.error(f"获取链接 {link} 时出错: {e}")

            adguard_rules = deduplicate_adguard_lines(raw_lines)
            if not adguard_rules:
                logging.warning(f"{rule_set_name} 没有可用 AdGuard 规则，跳过生成")
                return None

            with tempfile.TemporaryDirectory() as tmp_dir:
                logging.debug(f"创建临时目录: {tmp_dir}")
                adguard_file_path = os.path.join(tmp_dir, "adguard_combined.txt")

                # 将去重后的行写入临时文件
                with open(adguard_file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(adguard_rules))

                # 执行 sing-box 转换为 srs 格式
                srs_file_path = os.path.join(output_directory, "{}.srs".format(rule_set_name))
                conversion_command = [
                    "sing-box", "rule-set", "convert", "--type", "adguard",
                    "--output", srs_file_path, adguard_file_path
                ]
                run_command(conversion_command, f"转换 AdGuard 规则 {rule_set_name}")

                # 确认 .srs 文件已经生成
                if not os.path.exists(srs_file_path):
                    logging.error(f"转换失败，没有找到生成的 SRS 文件: {srs_file_path}")
                    return None

        except Exception as e:
            logging.error(f"处理 AdGuard 文件时出错: {e}")
            return None

    def parse_littlesnitch_file(self, link, retries=3, delay=5):
        """
        处理 Little Snitch 链接并返回解析后的 JSON 数据。
        """
        try:
            logging.debug(f"正在处理 Little Snitch 链接: {link}")

            for attempt in range(retries):
                try:
                    response = requests.get(link, timeout=config.request_timeout)
                    response.raise_for_status()  # 如果请求失败，抛出异常
                    break  # 请求成功，退出循环
                except requests.exceptions.RequestException as e:
                    logging.error(f"请求失败: {e}")
                    if attempt < retries - 1:  # 如果不是最后一次尝试
                        # logging.info(f"等待 {delay} 秒后重试...")
                        time.sleep(delay)  # 等待一段时间再重试
                    else:
                        logging.error(f"已达到最大重试次数 ({retries})，停止请求。")
                        return None

            raw_data = response.text
            logging.debug(f"获取到的原始数据: {raw_data[:500]}")  # 打印前 500 个字符

            # 清理数据
            cleaned_raw_data = clean_json_data(raw_data)
            logging.debug(f"清理后的数据: {cleaned_raw_data[:500]}")

            # 解析 JSON 数据
            data = json.loads(cleaned_raw_data)
            logging.debug(f"解析后的 JSON 数据: {data}")

            # 获取被拒绝的域名
            denied_domains = data.get("denied-remote-domains", [])
            cleaned_denied_domains = clean_denied_domains(denied_domains)

            # 检查是否找到了有效的拒绝域名数据
            if not (cleaned_denied_domains["domain"] or cleaned_denied_domains["domain_suffix"]):
                logging.warning(f"从 {link} 未找到 'denied-remote-domains' 数据")
                return None

            # 准备输出数据
            output_data = {
                "rules": [
                    {
                        "domain": cleaned_denied_domains["domain"],
                        "domain_suffix": cleaned_denied_domains["domain_suffix"]
                    }
                ],
                "version": 1
            }

            logging.debug(f"成功解析链接 {link}，生成 JSON 数据")
            return output_data

        except json.JSONDecodeError:
            logging.error(f"解析 JSON 时出错，从链接 {link} 读取的内容可能不是有效的 JSON。")
            return None
        except Exception as e:
            logging.error(f"处理链接 {link} 时发生未知错误：{e}")
            return None

    def parse_yaml_file(self, yaml_file, output_directory):
        """
        解析 YAML 文件中的链接，并根据类别生成相应的 JSON 文件。
        """
        with open(yaml_file, 'r') as file:
            data = yaml.safe_load(file)
            logging.debug(f"解析的 YAML 数据: {data}")

        # 按类别存储链接
        geosite_links = data.get('geosite', [])
        geoip_links = data.get('geoip', [])
        process_links = data.get('process', [])

        # 定义生成文件的路径
        rule_set_name = os.path.basename(yaml_file).split('.')[0]

        geosite_file = os.path.join(output_directory, f"geosite-{rule_set_name}.json")
        geoip_file = os.path.join(output_directory, f"geoip-{rule_set_name}.json")
        process_file = os.path.join(output_directory, f"process-{rule_set_name}.json")

        # 初始化结果存储
        final_results = []

        # 处理 geosite
        if geosite_links:
            geosite_result = self.generate_json_file(geosite_links, geosite_file, rule_set_name, type='geosite')
            final_results.append(("geosite", geosite_result))

        # 处理 geoip
        if geoip_links:
            geoip_result = self.generate_json_file(geoip_links, geoip_file, rule_set_name, type='geoip')
            final_results.append(("geoip", geoip_result))

        # 处理 process
        if process_links:
            process_result = self.generate_json_file(process_links, process_file, rule_set_name, type='process')
            final_results.append(("process", process_result))

        # 输出最终处理结果
        logging.info(f"{rule_set_name} 规则整理完成:")
        for result_type, result_data in final_results:
            logging.info(
                f"类型: {result_type}\n"
                f"domain 被过滤掉的条目数量: {result_data['filtered_count']}\n"
                f"剩余规则总数: {result_data['total_rules']}\n"
                f"规则分析:\n"
                f"  domain 条目数: {result_data['domain_count']}\n"
                f"  domain_suffix 条目数: {result_data['domain_suffix_count']}\n"
                f"  ip_cidr 条目数: {result_data['ip_cidr_count']}\n"
                f"  process_name 条目数: {result_data['process_name_count']}\n"
                f"  domain_regex 条目数: {result_data['domain_regex_count']}\n"
                f"{'-' * 50}"
            )

    def download_srs_file(self, url):
        """
        下载 .srs 文件到临时目录。
        """
        try:
            # 创建临时目录
            tmp_dir = tempfile.mkdtemp()
            srs_file_path = os.path.join(tmp_dir, os.path.basename(url))

            # 下载文件
            response = requests.get(url, timeout=config.request_timeout)
            response.raise_for_status()  # 确保请求成功
            with open(srs_file_path, 'wb') as file:
                file.write(response.content)

            # logging.info(f"成功下载 {url} 到 {srs_file_path}")
            return srs_file_path

        except Exception as e:
            logging.error(f"下载 {url} 时出错: {e}")
            return None

    def download_and_parse_json(self, json_file_url):
        """
        下载远程 JSON 文件到临时目录，并解析为 JSON 数据。
        """
        try:
            # logging.info(f"正在下载远程 JSON 文件: {json_file_url}")

            # 创建临时文件用于存储下载的 JSON 文件
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
                response = requests.get(json_file_url, stream=True, timeout=config.request_timeout)
                response.raise_for_status()  # 检查请求是否成功
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
                tmp_file_path = tmp_file.name  # 获取临时文件路径

            # logging.info(f"JSON 文件下载成功，临时路径: {tmp_file_path}")

            # 读取临时 JSON 文件
            with open(tmp_file_path, 'r', encoding='utf-8') as file:
                json_data = json.load(file)

            # 清理临时文件
            os.remove(tmp_file_path)
            # logging.info(f"已清理临时文件: {tmp_file_path}")

            return json_data

        except requests.exceptions.RequestException as e:
            logging.error(f"下载 JSON 文件失败: {json_file_url}, 错误: {e}")
        except json.JSONDecodeError as e:
            logging.error(f"解析 JSON 文件失败: {json_file_url}, 错误: {e}")
        except Exception as e:
            logging.error(f"处理 JSON 文件时出现未知错误: {e}")

        return None

    def generate_json_file(self, links, output_file, rule_set_name, type='geosite'):
        """
        生成合并后的 JSON 文件并返回处理统计信息。
        """
        # 去重链接
        unique_links = list(set(links))

        json_file_list = []
        for link in unique_links:
            json_file = self.parse_link_file_to_json(link)
            if json_file:
                json_file_list.append(json_file)
            else:
                logging.warning(f"跳过解析失败的链接: {link}")

        if not json_file_list:
            logging.warning(f"{rule_set_name} 没有可用规则，跳过生成: {output_file}")
            return {
                "filtered_count": 0,
                "total_rules": 0,
                "domain_count": 0,
                "domain_suffix_count": 0,
                "ip_cidr_count": 0,
                "process_name_count": 0,
                "domain_regex_count": 0,
            }

        # 如果只有一个 JSON 文件，直接保存，不调用 merge_json
        if len(json_file_list) == 1 and config.trust_upstream:
            single_file_stats = json_file_list[0]
            final_rules = single_file_stats.get("rules", [])

            # 如果 type 不是 'process'，则去除 process_name 条目 (debug)
            if type != 'process':
                final_rules = [
                    rule for rule in final_rules
                    if 'process_name' not in rule
                ]
            # 统计信息
            domain_count = sum(len(rule.get("domain", [])) for rule in final_rules)
            domain_suffix_count = sum(len(rule.get("domain_suffix", [])) for rule in final_rules)
            ip_cidr_count = sum(len(rule.get("ip_cidr", [])) for rule in final_rules)
            process_name_count = sum(len(rule.get("process_name", [])) for rule in final_rules)
            domain_regex_count = sum(len(rule.get("domain_regex", [])) for rule in final_rules)

            # 顶层信息
            statistics = {
                "filtered_count": 0,
                "total_rules": len(final_rules),
                "domain_count": domain_count,
                "domain_suffix_count": domain_suffix_count,
                "ip_cidr_count": ip_cidr_count,
                "process_name_count": process_name_count,
                "domain_regex_count": domain_regex_count
            }
            try:
                with open(output_file, 'w', encoding='utf-8') as file:
                    json.dump({"version": 1, "rules": final_rules}, file, ensure_ascii=False, indent=4)
            except Exception as e:
                logging.error(f"保存 JSON 文件时出错: {e}")
                return {"error": str(e)}
            # 返回统计信息
            return statistics
        # 否则调用 merge_json
        else:
            return self.merge_json(json_file_list, output_file, rule_set_name=rule_set_name, type=type)

    def merge_json(self, json_file_list, output_file, rule_set_name,
                   enable_trie_filtering=config.enable_trie_filtering, type='geosite'):
        """
        合并 JSON 文件并返回规则统计信息。
        """
        logging.debug(f"正在合并 JSON 文件: {json_file_list}")

        # 初始化合并规则
        merged_rules = {field: set() for field in RULE_VALUE_FIELDS}
        logical_rules = []
        seen_logical_rules = set()

        # 第一轮合并与去重
        for json_file in json_file_list:
            try:
                for rule in json_file.get("rules", []):
                    if isinstance(rule, dict):
                        if LOGICAL_RULE_KEYS.issubset(rule.keys()):
                            marker = make_hashable(rule)
                            if marker not in seen_logical_rules:
                                logical_rules.append(rule)
                                seen_logical_rules.add(marker)
                            continue
                        for category, values in rule.items():
                            if category in merged_rules and values:
                                if isinstance(values, list):
                                    merged_rules[category].update(values)
                                elif isinstance(values, str):
                                    merged_rules[category].add(values)
            except Exception as e:
                logging.error(f"解析 JSON 数据时出错: {e}")

        # 基于 domain_suffix 的 Trie 去重
        original_domain_count = len(merged_rules.get("domain", set()))
        filtered_count = 0
        final_domains = set()

        if enable_trie_filtering and merged_rules.get("domain_suffix"):
            if merged_rules.get("domain"):
                final_domains, filtered_count = filter_domains_with_trie(
                    merged_rules["domain"], merged_rules["domain_suffix"]
                )
            else:
                final_domains = merged_rules.get("domain", set())
        else:
            final_domains = merged_rules.get("domain", set())

        # 更新合并后的 domain 规则
        merged_rules["domain"] = final_domains

        # 转换为最终规则列表
        final_rules = logical_rules + [
            {category: sorted(values)}
            for category, values in merged_rules.items()
            if values
        ]

        # 如果 type 不是 'process'，则去除 process_name 条目 (debug)
        if type != 'process':
            final_rules = [
                rule for rule in final_rules
                if 'process_name' not in rule
            ]

        # 保存结果
        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                json.dump({"version": 1, "rules": final_rules}, file, ensure_ascii=False, indent=4)
        except Exception as e:
            logging.error(f"保存 JSON 文件时出错: {e}")

        # 返回统计信息
        return {
            "filtered_count": filtered_count,
            "total_rules": sum(len(values) for values in merged_rules.values()),
            "domain_count": len(merged_rules["domain"]),
            "domain_suffix_count": len(merged_rules["domain_suffix"]),
            "ip_cidr_count": len(merged_rules["ip_cidr"]),
            "process_name_count": len(merged_rules["process_name"]),
            "domain_regex_count": len(merged_rules["domain_regex"])
        }

    def decompile_srs_to_json(self, srs_file_url):
        """
        处理远程 .srs 文件，下载并使用 sing-box 的 decompile 命令转换为 JSON 文件。
        """
        try:
            # 下载 .srs 文件到临时目录
            srs_file = self.download_srs_file(srs_file_url)
            if not srs_file:
                logging.error(f"下载 .srs 文件失败: {srs_file_url}")
                return None

            # 解编译 SRS 文件为 JSON
            output_json_path = srs_file.replace(".srs", ".json")
            run_command(
                ["sing-box", "rule-set", "decompile", "--output", output_json_path, srs_file],
                f"解编译 SRS 文件 {srs_file_url}",
            )
            # logging.info(f"成功将 SRS 文件 {srs_file} 解编译为 JSON 文件 {output_json_path}")

            # 读取解编译后的 JSON 文件并返回
            with open(output_json_path, 'r', encoding='utf-8') as file:
                json_data = json.load(file)

            # 清理临时文件
            os.remove(srs_file)
            os.remove(output_json_path)

            return json_data

        except Exception as e:
            logging.error(f"处理 SRS 文件 {srs_file_url} 时出错: {e}")
            return None

    def parse_link_file_to_json(self, link):
        """
        解析给定的链接并返回处理后的 JSON 数据。
        """
        try:
            # logging.info(f"正在解析链接: {link}")

            if link.endswith('.json'):
                logging.debug(f"检测到 JSON 文件 {link}，直接返回内容")
                return self.download_and_parse_json(link)

            if link.endswith('.srs'):
                logging.debug(f"检测到 SRS 文件 {link}，正在进行解编译处理")
                json_file = self.decompile_srs_to_json(link)
                return json_file

            if any(keyword in link for keyword in config.ls_keyword):
                json_file = self.parse_littlesnitch_file(link)
                return json_file

            with concurrent.futures.ThreadPoolExecutor() as executor:
                results = list(executor.map(parse_and_convert_to_dataframe, [link]))
                dfs = [df for df, rules in results]
                logical_rules = [rule for _, rules in results for rule in rules]
                df = pd.concat(dfs, ignore_index=True)

            logging.debug(f"生成的 DataFrame: {df.head()}")
            if df.empty:
                return {"version": 1, "rules": logical_rules} if logical_rules else None

            df = df[~df['pattern'].str.contains('IP-CIDR6')].reset_index(drop=True)
            df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
            df = df[df['pattern'].isin(config.map_dict.keys())].reset_index(drop=True)
            df = df.drop_duplicates().reset_index(drop=True)
            df['pattern'] = df['pattern'].replace(config.map_dict)

            result_rules = {"version": 1, "rules": []}
            result_rules["rules"].extend(logical_rules)
            domain_entries = []
            for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
                if pattern == 'domain_suffix':
                    rule_entry = {pattern: [address.strip() for address in addresses]}
                    result_rules["rules"].append(rule_entry)
                elif pattern == 'domain':
                    domain_entries.extend([address.strip() for address in addresses])
                else:
                    rule_entry = {pattern: [address.strip() for address in addresses]}
                    result_rules["rules"].append(rule_entry)

            domain_entries = list(set(domain_entries))
            if domain_entries:
                result_rules["rules"].insert(0, {'domain': domain_entries})

            logging.debug(f"生成的 JSON 数据: {result_rules}")
            return result_rules

        except Exception as e:
            logging.error(f"解析链接 {link} 出现错误: {e}")
            return None

    def process_category_files(self, directory):
        # 找到包含 category 的文件并按类别分组
        category_files = [f for f in os.listdir(directory) if "category" in f and f.endswith('.json')]
        grouped_files = defaultdict(list)

        # 按类别分组文件，例如 geoip-category-communitaion.json -> geoip-category-communitaion
        for file in category_files:
            base_name = file.split("@")[0].replace(".json", "")
            grouped_files[base_name].append(file)

        # 分别处理每一组文件
        for category, files in grouped_files.items():
            logging.info(f"处理类别：{category}")
            self.process_single_category(directory, category, files)

    def process_single_category(self, directory, category, files):
        # 分组文件
        general_files = [f for f in files if "@" not in f]
        non_cn_files = [f for f in files if "@!cn" in f]
        cn_files = [f for f in files if "@cn" in f]

        # 如果没有全体文件，跳过
        if not general_files:
            logging.info(f"跳过处理 {category}，因为没有全体文件")
            return

        # 加载全体文件
        general_file_path = os.path.join(directory, general_files[0])
        general_data = load_json(general_file_path).get("rules", [])

        # 如果同时有 @cn 和 @!cn 文件
        if cn_files and non_cn_files:
            # 优先处理非 cn 文件
            cn_path = os.path.join(directory, cn_files[0])
            non_cn_path = os.path.join(directory, non_cn_files[0])

            cn_data = load_json(cn_path).get("rules", [])

            # 从全体文件中剔除 cn 文件的规则，剩余部分保存到 非cn 文件
            updated_non_cn_data = subtract_rules(general_data, cn_data)

            # @!cn 文件已存在，增量更新.
            non_cn_data = load_json(non_cn_path).get("rules", [])
            updated_non_cn_data = merge_rules(non_cn_data, updated_non_cn_data)

            # !cn 增量更新，cn不变
            final_non_cn_data = updated_non_cn_data
            final_cn_data = cn_data

            final_non_cn_data = deduplicate_json(final_non_cn_data)
            final_non_cn_data = convert_sets_to_lists(final_non_cn_data)

            # 保存去重后的非cn文件
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        # 只有 @cn 文件
        elif cn_files and not non_cn_files:
            cn_path = os.path.join(directory, cn_files[0])
            cn_data = load_json(cn_path).get("rules", [])

            # 从全体文件中剔除 cn 文件的规则，剩余部分保存到 非cn 文件
            non_cn_data = subtract_rules(general_data, cn_data)
            non_cn_path = os.path.join(directory, f"{category}@!cn.json")

            final_non_cn_data = non_cn_data  # 保存非cn数据
            final_cn_data = cn_data  # 保留原始的cn数据

            # 无须去重
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        # 只有 @!cn 文件
        elif non_cn_files and not cn_files:
            non_cn_path = os.path.join(directory, non_cn_files[0])
            non_cn_data = load_json(non_cn_path).get("rules", [])

            # 从全体文件中剔除 非cn 文件的规则，更新 cn 文件
            cn_data = subtract_rules(general_data, non_cn_data)
            cn_path = os.path.join(directory, f"{category}@cn.json")

            final_non_cn_data = non_cn_data  # 保留原始的非cn数据
            final_cn_data = cn_data  # 更新后的cn数据

            # 无须去重
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        else:
            logging.info(f"跳过处理 {category}，因为没有 @cn 或 @!cn 文件")
            return

        try:
            os.remove(general_file_path)
        except OSError as e:
            logging.error(f"删除全体文件 {general_files[0]} 失败: {e}")

    def apply_blacklist_fix(self, json_data, blacklist_data):
        """
        根据 blacklist_data 对 json_data 中的规则进行排除处理。

        排除逻辑：
        - blacklist domain 精确匹配：从目标 json 的 domain 列表中删除完全相同的条目
        - blacklist domain_suffix 后缀匹配：
            1. 从目标 json 的 domain 列表中删除所有以该后缀结尾的条目
               （例如 blacklist suffix="gstatic.com" 会删除 "foo.gstatic.com"、"gstatic.com" 等）
            2. 从目标 json 的 domain_suffix 列表中删除完全相同的条目
        - blacklist domain_suffix 同样对目标 json 的 domain_suffix 做精确排除
        """
        # 整理 blacklist 中的所有精确 domain 和 domain_suffix
        bl_domains = set()
        bl_suffixes = set()
        for rule in blacklist_data.get("rules", []):
            if isinstance(rule, dict):
                for d in rule.get("domain", []):
                    bl_domains.add(d.strip().lstrip("."))
                for s in rule.get("domain_suffix", []):
                    bl_suffixes.add(s.strip().lstrip("."))

        if not bl_domains and not bl_suffixes:
            return json_data  # blacklist 为空，直接返回

        removed_domain = 0
        removed_domain_suffix = 0

        new_rules = []
        for rule in json_data.get("rules", []):
            if not isinstance(rule, dict):
                new_rules.append(rule)
                continue

            new_rule = {}
            for key, values in rule.items():
                if not isinstance(values, list):
                    new_rule[key] = values
                    continue

                if key == "domain":
                    filtered = []
                    for entry in values:
                        entry_clean = entry.strip().lstrip(".")
                        # 精确 domain 排除
                        if entry_clean in bl_domains:
                            removed_domain += 1
                            continue
                        # domain_suffix 后缀包含关系排除
                        # entry 等于 suffix 本身，或者以 "." + suffix 结尾
                        matched_suffix = False
                        for suffix in bl_suffixes:
                            if entry_clean == suffix or entry_clean.endswith("." + suffix):
                                matched_suffix = True
                                break
                        if matched_suffix:
                            removed_domain += 1
                            continue
                        filtered.append(entry)
                    new_rule[key] = filtered

                elif key == "domain_suffix":
                    filtered = []
                    for entry in values:
                        entry_clean = entry.strip().lstrip(".")
                        # 精确 domain_suffix 排除
                        if entry_clean in bl_suffixes:
                            removed_domain_suffix += 1
                            continue
                        # blacklist domain 精确排除 domain_suffix
                        if entry_clean in bl_domains:
                            removed_domain_suffix += 1
                            continue
                        filtered.append(entry)
                    new_rule[key] = filtered

                else:
                    new_rule[key] = values

            # 只保留非空 rule
            if any(v for v in new_rule.values() if isinstance(v, list) and v) or \
               any(v for v in new_rule.values() if not isinstance(v, list)):
                new_rules.append(new_rule)

        json_data["rules"] = new_rules
        return json_data, removed_domain, removed_domain_suffix

    def apply_blacklist_to_output(self, output_directory, blacklist_directory="blacklist"):
        """
        遍历 output_directory 中所有 JSON 文件，
        若 blacklist_directory 中存在同名文件，则对其进行排除处理并回写。
        """
        if not os.path.isdir(blacklist_directory):
            logging.debug(f"blacklist 目录不存在，跳过 blacklist 修复: {blacklist_directory}")
            return

        json_files = [f for f in os.listdir(output_directory) if f.endswith('.json')]
        for json_file in json_files:
            bl_path = os.path.join(blacklist_directory, json_file)
            if not os.path.exists(bl_path):
                continue  # 同名 blacklist 不存在，跳过

            json_file_path = os.path.join(output_directory, json_file)
            try:
                with open(json_file_path, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                with open(bl_path, 'r', encoding='utf-8') as f:
                    blacklist_data = json.load(f)

                result = self.apply_blacklist_fix(json_data, blacklist_data)
                if isinstance(result, tuple):
                    fixed_data, rm_domain, rm_suffix = result
                else:
                    fixed_data = result
                    rm_domain = rm_suffix = 0

                with open(json_file_path, 'w', encoding='utf-8') as f:
                    json.dump(fixed_data, f, ensure_ascii=False, indent=4)

                logging.info(
                    f"[blacklist fix] {json_file}: "
                    f"domain 删除 {rm_domain} 条，domain_suffix 删除 {rm_suffix} 条"
                )
            except Exception as e:
                logging.error(f"[blacklist fix] 处理 {json_file} 时出错: {e}")

    def has_generated_rule_artifacts(self, output_directory):
        return any(
            f.endswith((".json", ".srs"))
            for f in os.listdir(output_directory)
        )

    def replace_output_directory(self, staging_directory, output_directory):
        backup_directory = None
        if os.path.exists(output_directory):
            backup_directory = tempfile.mkdtemp(prefix=".singbox-backup-", dir=config.rule_dir)
            shutil.rmtree(backup_directory)
            shutil.move(output_directory, backup_directory)

        try:
            shutil.move(staging_directory, output_directory)
        except Exception:
            if backup_directory and os.path.exists(backup_directory) and not os.path.exists(output_directory):
                shutil.move(backup_directory, output_directory)
            raise
        else:
            if backup_directory and os.path.exists(backup_directory):
                shutil.rmtree(backup_directory)

    def run(self):
        #### 解析规则，生成sing-box规则集
        source_directory = config.source_dir
        output_directory = config.singbox_output_directory
        os.makedirs(config.rule_dir, exist_ok=True)
        staging_directory = tempfile.mkdtemp(prefix=".singbox-staging-", dir=config.rule_dir)

        try:
            self.generate_singbox_rules(source_directory, staging_directory)
            if not self.has_generated_rule_artifacts(staging_directory):
                logging.error(
                    "本次没有生成任何 sing-box 规则产物，保留现有输出目录: %s",
                    output_directory,
                )
                shutil.rmtree(staging_directory)
                return False

            self.replace_output_directory(staging_directory, output_directory)
            staging_directory = None
        finally:
            if staging_directory and os.path.exists(staging_directory):
                shutil.rmtree(staging_directory)

        #### 调用工具函数 将 sing-box 规则转化为 Surge/Shadowrocket 规则
        convert_json_to_surge(output_directory)
        convert_json_to_clash(output_directory)

        convert_yaml_to_mrs(config.clash_output_directory)
        return True

    def main(self):
        return self.run()

    def generate_singbox_rules(self, source_directory, output_directory):
        yaml_files = sorted(f for f in os.listdir(source_directory) if f.endswith('.yaml'))
        for yaml_file in yaml_files:
            print('正在处理{}'.format(yaml_file))
            yaml_file_path = os.path.join(source_directory, yaml_file)
            # 检查 adg文件
            if any(keyword in yaml_file for keyword in config.adg_keyword):
                self.parse_adguard_file(yaml_file_path, output_directory)
            else:
                self.parse_yaml_file(yaml_file_path, output_directory)

        # 拆分 !cn 规则与 cn 规则
        self.process_category_files(output_directory)

        # ---- Blacklist Fix：在编译 srs 之前，先对 JSON 做排除处理 ----
        self.apply_blacklist_to_output(output_directory, blacklist_directory="blacklist")

        # 生成 SRS 文件
        json_files = sorted(f for f in os.listdir(output_directory) if f.endswith('.json'))
        for json_file in json_files:
            json_file_path = os.path.join(output_directory, json_file)
            srs_path = json_file_path.replace(".json", ".srs")
            run_command(
                ["sing-box", "rule-set", "compile", "--output", srs_path, json_file_path],
                f"编译 SRS 文件 {json_file}",
            )
            logging.debug(f"成功生成 SRS 文件 {srs_path}")
