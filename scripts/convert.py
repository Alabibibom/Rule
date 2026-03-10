#!/usr/bin/env python3
"""
Surge / Clash / Shadowrocket / QuantumultX / sing-box JSON
→ sing-box rule_set (JSON source format) converter
"""

import re, json, sys, time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import quote

RULES = [
    ("find_my",           "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/FindMy/FindMy.list",           "国内"),
    ("lan_non_ip",        "https://ruleset.skk.moe/List/non_ip/lan.conf",                                                                   "DIRECT"),
    ("lan_ip",            "https://ruleset.skk.moe/List/ip/lan.conf",                                                                       "DIRECT"),
    ("siri",              "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Siri/Siri.list",                "REJECT"),
    ("system_ota",        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/SystemOTA/SystemOTA.list",      "国内"),
    ("reject_drop",       "https://ruleset.skk.moe/List/non_ip/reject-drop.conf",                                                           "REJECT"),
    ("reject_domain",     "https://ruleset.skk.moe/List/domainset/reject.conf",                                                             "REJECT"),
    ("reject_non_ip",     "https://ruleset.skk.moe/List/non_ip/reject.conf",                                                                "REJECT"),
    ("reject_no_drop",    "https://ruleset.skk.moe/List/non_ip/reject-no-drop.conf",                                                        "REJECT"),
    ("reject_ip",         "https://ruleset.skk.moe/List/ip/reject.conf",                                                                    "REJECT"),
    ("synology",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Synology/Synology.list",        "群晖官方"),
    ("ai",                "https://ruleset.skk.moe/List/non_ip/ai.conf",                                                                    "国外"),
    ("apple_intelligence","https://ruleset.skk.moe/List/non_ip/apple_intelligence.conf",                                                    "国外"),
    ("github",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GitHub/GitHub.list",            "国外"),
    ("douyin",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/DouYin/DouYin.list",            "国内"),
    ("bilibili",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BiliBili/BiliBili.list",        "国内"),
    ("youtube",           "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/YouTube/YouTube.list",          "国外"),
    ("google",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Google/Google.list",            "国外"),
    ("tiktok",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/TikTok/TikTok.list",            "国外"),
    ("telegram_non_ip",   "https://ruleset.skk.moe/List/non_ip/telegram.conf",                                                              "国外"),
    ("telegram_ip",       "https://ruleset.skk.moe/List/ip/telegram.conf",                                                                  "国外"),
    ("telegram_asn",      "https://ruleset.skk.moe/List/ip/telegram_asn.conf",                                                              "国外"),
    ("wechat",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/WeChat/WeChat.list",            "国内"),
    ("apple_cn",          "https://ruleset.skk.moe/List/non_ip/apple_cn.conf",                                                              "国内"),
    ("appstore",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/AppStore/AppStore.list",        "苹果商店"),
    ("apple_services",    "https://ruleset.skk.moe/List/non_ip/apple_services.conf",                                                        "苹果"),
    ("apple_cdn",         "https://ruleset.skk.moe/List/domainset/apple_cdn.conf",                                                          "国内"),
    ("microsoft",         "https://ruleset.skk.moe/List/non_ip/microsoft.conf",                                                             "微软"),
    ("microsoft_cdn",     "https://ruleset.skk.moe/List/non_ip/microsoft_cdn.conf",                                                         "国内"),
    ("speedtest",         "https://ruleset.skk.moe/List/domainset/speedtest.conf",                                                          "测速"),
    ("amazon",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Amazon/Amazon.list",            "国外"),
    ("paypal",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PayPal/PayPal.list",            "国外"),
    ("china_domain",      "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/direct.txt",                                        "国内"),
    ("china_ip",          "https://ruleset.skk.moe/List/ip/china_ip.conf",                                                                  "国内"),
    ("china_ip_ipv6",     "https://ruleset.skk.moe/List/ip/china_ip_ipv6.conf",                                                             "国内"),
    # 自定义规则
    ("deepseek",          "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/DeepSeek.txt",          "国外"),
    ("obsidian",          "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/Obsidian插件.txt",      "国内"),
    ("emby",              "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/Emby官方.txt",          "Emby官方"),
    ("reject_custom",     "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/拒绝联网.txt",          "REJECT"),
    ("vps",               "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/VPS.txt",               "国内"),
    ("wuyouxing",         "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/无忧行.txt",            "无忧行"),
    ("special_cn",        "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/特殊放行国内.txt",      "国内"),
    ("special_out",       "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/特殊放行国外.txt",      "国外"),
    ("unlock",            "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/解锁.txt",              "解锁"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ruleset-converter/1.0)"}


def encode_url(url: str) -> str:
    prefix = url[:8]
    rest = url[8:]
    host, _, path = rest.partition("/")
    encoded_path = quote(path, safe="/:@!$&'()*+,;=~.-_")
    return prefix + host + "/" + encoded_path


def fetch(url: str) -> list[str]:
    encoded = encode_url(url)
    for attempt in range(3):
        try:
            req = Request(encoded, headers=HEADERS)
            with urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8").splitlines()
        except Exception as e:
            if attempt == 2:
                raise
            print(f"   重试 {attempt + 1}/3: {e}")
            time.sleep(3)


def detect_format(lines: list[str]) -> str:
    """自动检测规则格式"""
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Clash/Mihomo: 以 "- " 开头
        if line.startswith("- "):
            return "clash"
        # sing-box JSON
        if line.startswith("{") or line.startswith("["):
            return "singbox"
        # QuantumultX: host, host-suffix, host-keyword, ip-cidr
        if re.match(r"^(host|host-suffix|host-keyword|ip-cidr|ip6-cidr),", line, re.I):
            return "quantumultx"
        # Shadowrocket: 和 Surge 格式基本一致，DOMAIN/IP-CIDR 开头
        # Surge/Shadowrocket: DOMAIN, DOMAIN-SUFFIX, IP-CIDR 等
        if re.match(r"^(DOMAIN|IP-CIDR|PROCESS-NAME|URL-REGEX)", line):
            return "surge"
        # domainset: 纯域名或 .开头
        if re.match(r"^\.?[a-zA-Z0-9]", line) and "," not in line:
            return "domainset"
    return "surge"  # 默认


def parse_surge(lines: list[str]) -> dict:
    """解析 Surge / Shadowrocket / domainset 格式"""
    domains, domain_suffixes, domain_keywords, domain_regex = [], [], [], []
    ip_cidrs = []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # domainset 格式（无逗号的纯域名行）
        if "," not in line:
            if line.startswith("."):
                domain_suffixes.append(line[1:])
            else:
                # 过滤掉明显不是域名的行
                if re.match(r"^[a-zA-Z0-9][\w\-\.]*\.[a-zA-Z]{2,}$", line):
                    domains.append(line)
            continue

        line = re.sub(r"\s*#.*$", "", line).strip()
        if not line:
            continue

        parts = [p.strip() for p in line.split(",")]
        rule_type = parts[0].upper() if parts else ""

        if rule_type == "DOMAIN" and len(parts) >= 2:
            domains.append(parts[1])
        elif rule_type == "DOMAIN-SUFFIX" and len(parts) >= 2:
            domain_suffixes.append(parts[1])
        elif rule_type == "DOMAIN-KEYWORD" and len(parts) >= 2:
            domain_keywords.append(parts[1])
        elif rule_type == "DOMAIN-REGEX" and len(parts) >= 2:
            domain_regex.append(parts[1])
        elif rule_type in ("IP-CIDR", "IP-CIDR4", "IP-CIDR6") and len(parts) >= 2:
            ip_cidrs.append(parts[1])

    rule = {}
    if domains:          rule["domain"]         = sorted(set(domains))
    if domain_suffixes:  rule["domain_suffix"]   = sorted(set(domain_suffixes))
    if domain_keywords:  rule["domain_keyword"]  = sorted(set(domain_keywords))
    if domain_regex:     rule["domain_regex"]    = sorted(set(domain_regex))
    if ip_cidrs:         rule["ip_cidr"]         = sorted(set(ip_cidrs))
    return rule


def parse_clash(lines: list[str]) -> dict:
    """解析 Clash / Mihomo 格式（- TYPE,value,policy）"""
    domains, domain_suffixes, domain_keywords, domain_regex = [], [], [], []
    ip_cidrs = []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # 去掉开头的 "- "
        if line.startswith("- "):
            line = line[2:].strip()
        # 也支持 payload: 下的纯域名行
        if line.startswith("'") or line.startswith('"'):
            line = line.strip("'\"")

        line = re.sub(r"\s*#.*$", "", line).strip()
        if not line:
            continue

        parts = [p.strip() for p in line.split(",")]
        rule_type = parts[0].upper() if parts else ""

        if rule_type == "DOMAIN" and len(parts) >= 2:
            domains.append(parts[1])
        elif rule_type == "DOMAIN-SUFFIX" and len(parts) >= 2:
            domain_suffixes.append(parts[1])
        elif rule_type == "DOMAIN-KEYWORD" and len(parts) >= 2:
            domain_keywords.append(parts[1])
        elif rule_type == "DOMAIN-REGEX" and len(parts) >= 2:
            domain_regex.append(parts[1])
        elif rule_type in ("IP-CIDR", "IP-CIDR4", "IP-CIDR6", "IP-SUFFIX") and len(parts) >= 2:
            ip_cidrs.append(parts[1])
        # 纯域名（payload 列表格式）
        elif re.match(r"^[a-zA-Z0-9][\w\-\.]*\.[a-zA-Z]{2,}$", line) and "," not in line:
            if line.startswith("+."):
                domain_suffixes.append(line[2:])
            elif line.startswith("."):
                domain_suffixes.append(line[1:])
            else:
                domains.append(line)

    rule = {}
    if domains:          rule["domain"]         = sorted(set(domains))
    if domain_suffixes:  rule["domain_suffix"]   = sorted(set(domain_suffixes))
    if domain_keywords:  rule["domain_keyword"]  = sorted(set(domain_keywords))
    if domain_regex:     rule["domain_regex"]    = sorted(set(domain_regex))
    if ip_cidrs:         rule["ip_cidr"]         = sorted(set(ip_cidrs))
    return rule


def parse_quantumultx(lines: list[str]) -> dict:
    """解析 QuantumultX 格式（host,value / host-suffix,value / ip-cidr,value）"""
    domains, domain_suffixes, domain_keywords = [], [], []
    ip_cidrs = []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        line = re.sub(r"\s*#.*$", "", line).strip()
        if not line:
            continue

        parts = [p.strip() for p in line.split(",")]
        rule_type = parts[0].lower() if parts else ""

        if rule_type == "host" and len(parts) >= 2:
            domains.append(parts[1])
        elif rule_type == "host-suffix" and len(parts) >= 2:
            domain_suffixes.append(parts[1])
        elif rule_type == "host-keyword" and len(parts) >= 2:
            domain_keywords.append(parts[1])
        elif rule_type in ("ip-cidr", "ip6-cidr") and len(parts) >= 2:
            ip_cidrs.append(parts[1])

    rule = {}
    if domains:          rule["domain"]         = sorted(set(domains))
    if domain_suffixes:  rule["domain_suffix"]   = sorted(set(domain_suffixes))
    if domain_keywords:  rule["domain_keyword"]  = sorted(set(domain_keywords))
    if ip_cidrs:         rule["ip_cidr"]         = sorted(set(ip_cidrs))
    return rule


def parse_singbox_json(lines: list[str]) -> dict:
    """解析 sing-box rule_set JSON 源格式，直接提取 rules"""
    try:
        data = json.loads("\n".join(lines))
        rules = data.get("rules", [])
        if rules:
            # 合并所有 rule 块
            merged: dict = {}
            for r in rules:
                for k, v in r.items():
                    if isinstance(v, list):
                        merged.setdefault(k, [])
                        merged[k].extend(v)
                    else:
                        merged[k] = v
            # 去重排序
            return {k: sorted(set(v)) if isinstance(v, list) else v
                    for k, v in merged.items()}
    except Exception:
        pass
    return {}


def parse(lines: list[str]) -> dict:
    fmt = detect_format(lines)
    print(f"   📄 检测格式: {fmt}")
    if fmt == "clash":
        return parse_clash(lines)
    elif fmt == "quantumultx":
        return parse_quantumultx(lines)
    elif fmt == "singbox":
        return parse_singbox_json(lines)
    else:
        return parse_surge(lines)


def to_singbox_source(rule: dict) -> dict:
    return {
        "version": 2,
        "rules": [rule] if rule else []
    }


def main():
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    errors = []
    for name, url, tag in RULES:
        print(f"⬇  {name} ← {url}")
        try:
            lines = fetch(url)
            rule  = parse(lines)
            data  = to_singbox_source(rule)
            dest  = out_dir / f"{name}.json"
            dest.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            n = sum(len(v) if isinstance(v, list) else 1 for v in rule.values())
            print(f"   ✓ {n} 条 → {dest}")
        except Exception as e:
            print(f"   ✗ 失败: {e}", file=sys.stderr)
            errors.append((name, str(e)))

    if errors:
        print("\n⚠  以下规则下载失败：")
        for n, e in errors:
            print(f"   {n}: {e}")
        sys.exit(1)

    print("\n✅ 全部完成")


if __name__ == "__main__":
    main()
