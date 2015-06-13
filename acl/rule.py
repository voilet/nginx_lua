#!/usr/bin/env python
# -*- coding: utf-8 -*-
# =============================================================================
#     FileName: rule.py
#         Desc: 2015-15/3/9:下午5:39
#       Author: 苦咖啡
#        Email: voilet@qq.com
#     HomePage: http://blog.kukafei520.net
#      History: 
# =============================================================================

# sql注入漏洞
atk_data = {
    #   SQL
    "\$\{": u"sql注入",
    "select.+(from|limit)": u"sql注入",
    "(?:(union(.*?)select))": u"sql注入",
    "having|rongjitest": u"sql注入",
    "sleep\((\s*)(\d*)(\s*)\)": u"sql注入",
    "benchmark\((.*)\,(.*)\)": u"sql注入",
    "base64_decode\(": u"sql注入",
    "(?:from\W+information_schema\W)": u"sql注入",
    "(?:(?:current_)user|database|schema|connection_id)\s*\(": u"sql注入",
    "into(\s+)+(?:dump|out)file\s*": u"sql注入",
    "group\s+by.+\(": u"sql注入",

    # cmd webshell可触发规则
    "(?:define|eval|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|alert|showmodaldialog)\(": u"命令执行",
    "java\.lang": u"命令执行",
    "xwork.MethodAccessor": u"命令执行",
    "xwork\.MethodAccessor": u"命令执行",
    "\$_(GET|post|cookie|files|session|env|phplib|GLOBALS|SERVER)\[": u"命令执行",

    # 文件加载漏洞
     "(gopher|doc|php|glob|file|phar|zlib|ftp|ldap|dict|ogg|data)\:\/": u"文件加载",
    "(?:etc\/\W*passwd)": u"文件加载",
    "\.\./": u"文件包含",

    #   xss
    "\<(iframe|script|body|img|layer|div|meta|style|base|object|input)": u"XSS攻击",
    "(onmouseover|onerror|onload)\=": u"XSS攻击",

    # hacker scan
    '(HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|Nikto|fimap|havij|PycURL|zmeu|BabyKrokodil|netsparker|httperf| SF/)': u"黑客扫描",

    # file scan
    "/(attachments|upimg|images|css|uploadfiles|html|uploads|templets|static|template|data|inc|forumdata|upload|includes|cache|avatar)/(\\w+).(php|jsp)": u"目录探测",
    "(phpmyadmin|jmx-console|jmxinvokerservlet)": u"敏感文件",
    "(vhost|bbs|host|wwwroot|www|site|root|hytop|flashfxp).*.rar": u"敏感文件",
    "\.(bak|inc|old|mdb|sql|backup|java|class)$": u"敏感文件",

}

def atk(rule):
    """

    :param rule:
    :return:
    """
    data = atk_data.get(rule, "异常请求")
    return data

# s = "(HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|Nikto|fimap|havij|PycURL|zmeu|BabyKrokodil|netsparker|httperf| SF/)"
# # print repr(s)
# print atk(s)