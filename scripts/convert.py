#!/usr/bin/env python3
"""
Surge ruleset → sing-box rule_set (JSON source format) converter
"""

import re, json, sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

# ── 远程规则映射表（去掉本地 .txt） ──────────────────────────────────────────
RULES = [
    # (输出文件名,  远程 URL,  outbound/tag)
    ("find_my",         "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/FindMy/FindMy.list",           "国内"),
    ("lan_non_ip",      "https://ruleset.skk.moe/List/non_ip/lan.conf",                                                                    "DIRECT"),
    ("lan_ip",          "https://ruleset.skk.moe/List/ip/lan.conf",                                                                        "DIRECT"),
    ("siri",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Siri/Siri.list",                 "REJECT"),
    ("system_ota",      "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/SystemOTA/SystemOTA.list",       "国内"),
    ("reject_drop",     "https://ruleset.skk.moe/List/non_ip/reject-drop.conf",                                                            "REJECT"),
    ("reject_domain",   "https://ruleset.skk.moe/List/domainset/reject.conf",                                                              "REJECT"),
    ("reject_non_ip",   "https://ruleset.skk.moe/List/non_ip/reject.conf",                                                                 "REJECT"),
    ("reject_no_drop",  "https://ruleset.skk.moe/List/non_ip/reject-no-drop.conf",                                                         "REJECT"),
    ("reject_ip",       "https://ruleset.skk.moe/List/ip/reject.conf",                                                                     "REJECT"),
    ("synology",        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Synology/Synology.list",         "群晖官方"),
    ("ai",              "https://ruleset.skk.moe/List/non_ip/ai.conf",                                                                     "国外"),
    ("apple_intelligence","https://ruleset.skk.moe/List/non_ip/apple_intelligence.conf",                                                   "国外"),
    ("github",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GitHub/GitHub.list",             "国外"),
    ("douyin",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/DouYin/DouYin.list",             "国内"),
    ("bilibili",        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BiliBili/BiliBili.list",         "国内"),
    ("youtube",         "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/YouTube/YouTube.list",           "国外"),
    ("google",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Google/Google.list",             "国外"),
    ("tiktok",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/TikTok/TikTok.list",             "国外"),
    ("telegram_non_ip", "https://ruleset.skk.moe/List/non_ip/telegram.conf",                                                               "国外"),
    ("telegram_ip",     "https://ruleset.skk.moe/List/ip/telegram.conf",                                                                   "国外"),
    ("telegram_asn",    "https://ruleset.skk.moe/List/ip/telegram_asn.conf",                                                               "国外"),
    ("wechat",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/WeChat/WeChat.list",             "国内"),
    ("apple_cn",        "https://ruleset.skk.moe/List/non_ip/apple_cn.conf",                                                               "国内"),
    ("appstore",        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/AppStore/AppStore.list",         "苹果商店"),
    ("apple_services",  "https://ruleset.skk.moe/List/non_ip/apple_services.conf",                                                         "苹果"),
    ("apple_cdn",       "https://ruleset.skk.moe/List/domainset/apple_cdn.conf",                                                           "国内"),
    ("microsoft",       "https://ruleset.skk.moe/List/non_ip/microsoft.conf",                                                              "微软"),
    ("microsoft_cdn",   "https://ruleset.skk.moe/List/non_ip/microsoft_cdn.conf",                                                          "国内"),
    ("speedtest",       "https://ruleset.skk.moe/List/domainset/speedtest.conf",                                                            "测速"),
    ("amazon",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Amazon/Amazon.list",             "国外"),
    ("paypal",          "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PayPal/PayPal.list",             "国外"),
    ("china_domain",    "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/direct.txt",                                         "国内"),
    ("china_ip",        "https://ruleset.skk.moe/List/ip/china_ip.conf",                                                                   "国内"),
    ("china_ip_ipv6",   "https://ruleset.skk.moe/List/ip/china_ip_ipv6.conf",                                                              "国内"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ruleset-converter/1.0)"}


def fetch(url: str) -> list[str]:
    req = Request(url, headers=HEADERS)
    with urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8").splitlines()


def parse_surge(lines: list[str]) -> dict:
    """解析 Surge list / conf / domainset，返回 sing-box rules dict"""
    domains, domain_suffixes, domain_keywords, domain_regex = [], [], [], []
    ip_cidrs, ip_cidr6s, process_names = [], [], []
    ports = []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # ── domainset 格式（纯域名，带 . 前缀表示后缀）────────────────────
        if line.startswith("."):
            domain_suffixes.append(line[1:])
            continue

        # ── Surge list 格式 ──────────────────────────────────────────────
        # 去掉行内注释
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
        elif rule_type in ("IP-CIDR", "IP-CIDR4") and len(parts) >= 2:
            ip_cidrs.append(parts[1])
        elif rule_type == "IP-CIDR6" and len(parts) >= 2:
            ip_cidr6s.append(parts[1])
        elif rule_type == "IP-ASN" and len(parts) >= 2:
            # sing-box 用 asn 字段
            pass  # sing-box source format 暂不支持 ASN，跳过
        elif rule_type == "PROCESS-NAME" and len(parts) >= 2:
            process_names.append(parts[1])
        elif rule_type == "DEST-PORT" and len(parts) >= 2:
            ports.append(parts[1])
        # USER-AGENT / URL-REGEX / GEOIP 等忽略

    rule = {}
    if domains:          rule["domain"] = sorted(set(domains))
    if domain_suffixes:  rule["domain_suffix"] = sorted(set(domain_suffixes))
    if domain_keywords:  rule["domain_keyword"] = sorted(set(domain_keywords))
    if domain_regex:     rule["domain_regex"] = sorted(set(domain_regex))
    if ip_cidrs:         rule["ip_cidr"] = sorted(set(ip_cidrs))
    if ip_cidr6s:        rule["ip_cidr"] += sorted(set(ip_cidr6s))  # 合并
    if process_names:    rule["process_name"] = sorted(set(process_names))
    return rule


def to_singbox_source(rule: dict, tag: str) -> dict:
    """包装成 sing-box rule_set source JSON"""
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
            rule  = parse_surge(lines)
            data  = to_singbox_source(rule, tag)
            dest  = out_dir / f"{name}.json"
            dest.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            n = sum(len(v) if isinstance(v, list) else 1 for v in rule.values())
            print(f"   ✓ {n} entries → {dest}")
        except (URLError, Exception) as e:
            print(f"   ✗ FAILED: {e}", file=sys.stderr)
            errors.append((name, str(e)))

    # 生成 sing-box route rules 片段供参考
    _write_route_snippet(out_dir)

    if errors:
        print("\n⚠  以下规则下载失败：")
        for n, e in errors:
            print(f"   {n}: {e}")
        sys.exit(1)
    print("\n✅ 全部完成")


def _write_route_snippet(out_dir: Path):
    """生成可直接贴进 sing-box config 的 route.rule_set + route.rules 片段"""
    rule_sets, rules = [], []

    for name, url, tag in RULES:
        rule_sets.append({
            "type": "local",
            "tag": name,
            "format": "source",
            "path": f"./ruleset/{name}.json"
        })
        rules.append({
            "rule_set": name,
            "outbound": tag
        })

    snippet = {
        "_comment": "将 rule_set 和 rules 合并进你的 sing-box config.json",
        "route": {
            "rule_set": rule_sets,
            "rules": rules,
            "final": "国外"
        }
    }
    path = out_dir / "_route_snippet.json"
    path.write_text(json.dumps(snippet, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"   📋 路由片段 → {path}")


if __name__ == "__main__":
    main()
