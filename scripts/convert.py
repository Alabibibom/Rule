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
    # 查找
    ("find_my_device",           "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/FindMy/FindMy.list"),
    # 局域网 Non IP
    ("lan_non_ip",        "https://ruleset.skk.moe/List/non_ip/lan.conf"),
    # 局域网 IP
    ("lan_ip",            "https://ruleset.skk.moe/List/ip/lan.conf"),
    # siri
    ("siri",              "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Siri/Siri.list"),
    # iOS升级
    ("ios_ota",        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/SystemOTA/SystemOTA.list"),
    # 拦截 1.统计类 reject-drop
    ("reject_survey",       "https://ruleset.skk.moe/List/non_ip/reject-drop.conf"),
    # 拦截 2.基础12万拦截域名 reject
    ("reject_basic",     "https://ruleset.skk.moe/List/domainset/reject.conf"),
    # 拦截 3.额外 9 万拦截域名，作为基础的补充，启用时需要搭配基础一起使用reject
    ("reject_extra",     "https://ruleset.skk.moe/List/domainset/reject_extra.conf"),
    # 拦截 4.钓鱼网站拦截域名列表，共 13 万拦截域名
	# 拦截 4.1.通用规则 reject
    ("reject_fishing1",     "https://ruleset.skk.moe/List/non_ip/reject.conf"),
    # 拦截 4.1.通用规则 reject-no-drop
    ("reject_fishing2",    "https://ruleset.skk.moe/List/non_ip/reject-no-drop.conf"),
    # 拦截 4.2.Mac专用，担心ios内存不够。surge考虑，singbox无视。reject
    ("reject_mac_prefer",   "https://ruleset.skk.moe/List/domainset/reject_phishing.conf"),
    # 拦截 6.IP
    ("reject_ip",         "https://ruleset.skk.moe/List/ip/reject.conf"),
    # 群晖官方
    ("synology",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Synology/Synology.list"),
    # 其他AI
    ("ai",                "https://ruleset.skk.moe/List/non_ip/ai.conf"),
    ("apple_intelligence","https://ruleset.skk.moe/List/non_ip/apple_intelligence.conf"),
    # GitHub
    ("github",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GitHub/GitHub.list"),
    # 抖音
    ("douyin",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/DouYin/DouYin.list"),
    # 哔哩哔哩
    ("bilibili",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BiliBili/BiliBili.list"),
    # YouTube
    ("youtube",           "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/YouTube/YouTube.list"),
    # 谷歌
    ("google",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Google/Google.list"),
    # Tiktok
    ("tiktok",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/TikTok/TikTok.list"),
    # Telegram
    ("telegram_non_ip",   "https://ruleset.skk.moe/List/non_ip/telegram.conf"),
    ("telegram_ip",       "https://ruleset.skk.moe/List/ip/telegram.conf"),
    ("telegram_asn",      "https://ruleset.skk.moe/List/ip/telegram_asn.conf"),
    # Wechat
    ("wechat",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/WeChat/WeChat.list"),
    # 苹果 1.1.Apple 中国大陆特供（必须直连）
    ("apple_cn",          "https://ruleset.skk.moe/List/non_ip/apple_cn.conf"),
    # 苹果 1.2.Apple Store
    ("appstore",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/AppStore/AppStore.list"),
    # 苹果 1.3.Apple 全球服务
    ("apple_services",    "https://ruleset.skk.moe/List/non_ip/apple_services.conf"),
    # 苹果 1.3.Apple 国内 CDN
    ("apple_cdn",         "https://ruleset.skk.moe/List/domainset/apple_cdn.conf"),
    # 微软 1.1.微软全球服务
    ("microsoft",         "https://ruleset.skk.moe/List/non_ip/microsoft.conf"),
    # 微软 1.2.微软国内 CDN
    ("microsoft_cdn",     "https://ruleset.skk.moe/List/non_ip/microsoft_cdn.conf"),
    # Speedtest
    ("speedtest",         "https://ruleset.skk.moe/List/domainset/speedtest.conf"),
    # 亚马逊
    ("amazon",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Amazon/Amazon.list"),
    # Paypal
    ("paypal",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PayPal/PayPal.list"),
    # 中国域名
    ("china_domain",      "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/direct.txt"),
    # 中国 IP IPv4
    ("china_ip",          "https://ruleset.skk.moe/List/ip/china_ip.conf"),
    # 中国 IP IPv6
    ("china_ip_ipv6",     "https://ruleset.skk.moe/List/ip/china_ip_ipv6.conf"),
    # 自定义规则
    # DeepSeek
    ("deepseek",          "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/DeepSeek.txt"),
    # Obsidian插件
    ("obsidian",          "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/Obsidian插件.txt"),
    # Emby官方
    ("emby",              "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/Emby官方.txt"),
    # 拒绝联网
    ("spicial_reject",     "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/拒绝联网.txt"),
    # VPS
    ("vps",               "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/VPS.txt"),
    # 无忧行
    ("wuyouxing",         "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/无忧行.txt"),
    # 特殊放行国内
    ("special_cn",        "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/特殊放行国内.txt"),
    # 特殊放行国外
    ("special_out",       "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/特殊放行国外.txt"),
    # 特殊解锁
    ("special_ cunlock",            "https://raw.githubusercontent.com/Alabibibom/Rule/main/custom/解锁.txt"),
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
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            return "clash"
        if line.startswith("{") or line.startswith("["):
            return "singbox"
        if re.match(r"^(host|host-suffix|host-keyword|ip-cidr|ip6-cidr),", line, re.I):
            return "quantumultx"
        if re.match(r"^(DOMAIN|IP-CIDR|PROCESS-NAME|URL-REGEX)", line):
            return "surge"
        if re.match(r"^\.?[a-zA-Z0-9]", line) and "," not in line:
            return "domainset"
    return "surge"


def parse_surge(lines: list[str]) -> dict:
    domains, domain_suffixes, domain_keywords, domain_regex = [], [], [], []
    ip_cidrs = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "," not in line:
            if line.startswith("."):
                domain_suffixes.append(line[1:])
            else:
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
    domains, domain_suffixes, domain_keywords, domain_regex = [], [], [], []
    ip_cidrs = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
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
    try:
        data = json.loads("\n".join(lines))
        rules = data.get("rules", [])
        if rules:
            merged: dict = {}
            for r in rules:
                for k, v in r.items():
                    if isinstance(v, list):
                        merged.setdefault(k, [])
                        merged[k].extend(v)
                    else:
                        merged[k] = v
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
    for name, url in RULES:
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
