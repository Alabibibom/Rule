#!/usr/bin/env python3
"""
Surge ruleset → sing-box rule_set (JSON source format) converter
"""

import re, json, sys, time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

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
    ("speedtest",         "https://ruleset.skk.moe/List/domainset/speedtest.conf",                                                           "测速"),
    ("amazon",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Amazon/Amazon.list",            "国外"),
    ("paypal",            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PayPal/PayPal.list",            "国外"),
    ("china_domain",      "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/direct.txt",                                        "国内"),
    ("china_ip",          "https://ruleset.skk.moe/List/ip/china_ip.conf",                                                                  "国内"),
    ("china_ip_ipv6",     "https://ruleset.skk.moe/List/ip/china_ip_ipv6.conf",                                                             "国内"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ruleset-converter/1.0)"}


def fetch(url: str) -> list[str]:
    for attempt in range(3):
        try:
            req = Request(url, headers=HEADERS)
            with urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8").splitlines()
        except Exception as e:
            if attempt == 2:
                raise
            print(f"   重试 {attempt + 1}/3: {e}")
            time.sleep(3)


def parse_surge(lines: list[str]) -> dict:
    domains, domain_suff​​​​​​​​​​​​​​​​
