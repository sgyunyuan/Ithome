# encoding:utf-8
"""
@author:zixing
@email:zixing131@qq.com
@date:2018-08-28 11:37
#2020-03-08 添加云日历windows客户端签到
#2026-11-05 添加 shangguan 推送签到结果
"""

import binascii
import os
import time
import urllib.request
import urllib.parse
from datetime import datetime

import requests
from pyDes import des, ECB

# ══════════════════ 配置 ══════════════════

# 秘钥
KEY = "+f/1+hfh"

# shangguan 推送接口
PUSH_URL = "https://api.chuckfang.com/shangguan/"

# 签到用户 hash：优先读环境变量 ITHOME_USERHASH，否则用占位值
USERHASH = os.environ.get("ITHOME_USERHASH", "sign")

# 是否推送：设 ITHOME_PUSH=0 可关闭推送（默认开）
PUSH_ENABLED = os.environ.get("ITHOME_PUSH", "1").strip() != "0"

# 接口超时（秒）
REQUEST_TIMEOUT = 20


# ══════════════════ DES 加解密 ══════════════════

def make_up_data(data: str, mode: str = "PAD_ZERO"):
    pad = 8 - len(data) % 8
    pad_str = ''
    if mode == "PAD_PKCS5":
        for _ in range(pad):
            pad_str += chr(pad)
    elif mode == "PAD_ZERO":
        for _ in range(pad):
            pad_str += chr(0)
    return data + pad_str


def des_encrypt(s: str):
    """DES 加密，返回 16 进制字符串"""
    s = make_up_data(s)
    secret_key = KEY
    iv = secret_key
    k = des(secret_key, ECB, iv, pad=None)
    en = k.encrypt(s)
    return binascii.b2a_hex(en)


def des_encrypt2(s: str, key: str):
    """DES 加密（指定 key），返回 str"""
    s = make_up_data(s)
    secret_key = key
    iv = secret_key
    k = des(secret_key, ECB, iv, pad=None)
    en = k.encrypt(s)
    return binascii.b2a_hex(en).decode()


def des_descrypt(s: str) -> str:
    """DES 解密"""
    secret_key = KEY
    iv = secret_key
    k = des(secret_key, ECB, iv, pad=None)
    de = k.decrypt(binascii.a2b_hex(s))
    return de


# ══════════════════ 时间 / 工具 ══════════════════

def cn(x: bytes):
    return x.decode("u8")


def getNowTime13():
    return str(int(round(time.time() * 1000)))


def getNowTime132(dtime: datetime):
    print((str(int(time.mktime(dtime.timetuple()) * 1000))))
    return str(int(time.mktime(dtime.timetuple()) * 1000))


def getTime(dtime: datetime):
    return int(time.mktime(dtime.timetuple())) * 1000


def getDate(dtime: datetime):
    return dtime.day


def getDate2(dtime: int):
    dtime: datetime = datetime.fromtimestamp(dtime / 1000)
    return dtime.day


def parseInt(data: float):
    return int(data)


# ══════════════════ 签名参数生成 ══════════════════

def geKK(_0x249526: datetime, _0x2fce26: int):
    _0x17c13c = "hd7%b4f8p9)*fd4h5l6|)123/*-+!#$@%^*()_+?>?njidfds[]rfbcvnb3rz/ird|opqqyh487874515/%90hggigadfihklhkopjj`b3hsdfdsf84215456fi15451%q(#@Fzd795hn^Ccl$vK^L%#w$^yr%ETvX#0TaPSRm5)OeG)^fQnn6^%^UTtJI#3EZ@p6^Rf$^!O$(jnkOiBjn3#inhOQQ!aTX8R)9O%#o3zCVxo3tLyVorwYwA^$%^b9Yy$opSEAOOlFBsS^5d^HoF%tJ$dx%3)^q^c^$al%b4I)QHq^#^AlcK^KZFYf81#bL$n@$%j^H(%m^"
    _0x5c548d = getTime(_0x249526)
    _0x5c59ee = getDate(_0x249526)
    _0x5c548d = round(_0x5c548d / 0xC350) * _0x5c59ee * 0x3
    if _0x2fce26 == 3:
        return (
            _0x17c13c[parseInt(_0x5c548d % 0x2710 / 0x3E8) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x3E8 / 0x64) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x64 / 0xA) * _0x5c59ee]
        )
    elif _0x2fce26 == 8:
        return (
            _0x17c13c[parseInt(_0x5c548d % 0x5F5E100 / 0x989680) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x989680 / 0xF4240) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0xF4240 / 0x186A0) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x186A0 / 0x2710) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x2710 / 0x3E8) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x3E8 / 0x64) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x64 / 0xA) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0xA) * _0x5c59ee]
        )
    else:
        return None


def geKK2(_0x249526: int, _0x2fce26: int):
    _0x17c13c = "hd7%b4f8p9)*fd4h5l6|)123/*-+!#$@%^*()_+?>?njidfds[]rfbcvnb3rz/ird|opqqyh487874515/%90hggigadfihklhkopjj`b3hsdfdsf84215456fi15451%q(#@Fzd795hn^Ccl$vK^L%#w$^yr%ETvX#0TaPSRm5)OeG)^fQnn6^%^UTtJI#3EZ@p6^Rf$^!O$(jnkOiBjn3#inhOQQ!aTX8R)9O%#o3zCVxo3tLyVorwYwA^$%^b9Yy$opSEAOOlFBsS^5d^HoF%tJ$dx%3)^q^c^$al%b4I)QHq^#^AlcK^KZFYf81#bL$n@$%j^H(%m^"
    _0x5c548d = _0x249526
    _0x5c59ee = getDate2(_0x249526)
    _0x5c548d = round(_0x5c548d / 0xC350) * _0x5c59ee * 0x3
    if _0x2fce26 == 3:
        return (
            _0x17c13c[parseInt(_0x5c548d % 0x2710 / 0x3E8) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x3E8 / 0x64) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x64 / 0xA) * _0x5c59ee]
        )
    elif _0x2fce26 == 8:
        return (
            _0x17c13c[parseInt(_0x5c548d % 0x5F5E100 / 0x989680) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x989680 / 0xF4240) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0xF4240 / 0x186A0) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x186A0 / 0x2710) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x2710 / 0x3E8) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x3E8 / 0x64) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0x64 / 0xA) * _0x5c59ee]
            + _0x17c13c[parseInt(_0x5c548d % 0xA) * _0x5c59ee]
        )
    else:
        return None


def gneKK(_0x4060f6: datetime):
    return 'k' + des_encrypt2(geKK(_0x4060f6, 3), geKK(_0x4060f6, 8))


def geKsK(_0x101b3e: datetime):
    return des_encrypt2(_0x101b3e.strftime("%Y-%m-%d %H:%M:%S"), geKK(_0x101b3e, 8))


def gneKK2(_0x4060f6: int):
    return 'k' + des_encrypt2(geKK2(_0x4060f6, 3), geKK2(_0x4060f6, 8))


def geKsK2(_0x101b3e: float):
    return des_encrypt2(
        datetime.fromtimestamp(_0x101b3e / 1000).strftime("%Y-%m-%d %H:%M:%S"),
        geKK2(_0x101b3e, 8),
    )


# ══════════════════ IT之家签到 ══════════════════

class ITHomeSign:
    def __init__(self, userhash: str):
        self.urlhead = "http://my.ruanmei.com/"
        self.userhash = userhash
        self.UA = (
            "Mozilla/5.0 (Linux; Android 10; Redmi K30 5G Build/QKQ1.191222.002; wv) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.101 "
            "Mobile Safari/537.36 ithome/rmsdklevel2/day/7.37"
        )

    def getSign(self):
        now = int(time.time() * 1000)
        return "&timestamp=" + str(now) + "&" + gneKK2(now) + "=" + geKsK2(now)

    def sign(self):
        headers = {
            "Referer": "https://my.ruanmei.com/app/user/signin.html?hidemenu=1&appver=2"
        }
        url = (
            self.urlhead
            + "api/usersign/sign?userHash="
            + self.userhash
            + "&type=0"
            + self.getSign()
        )
        result = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        return result.content

    def signlapin(self):
        url = (
            self.urlhead
            + "/api/usersign/sign?userHash="
            + self.userhash
            + "&type=1&platform=lapinapp_android&channel=official"
            + self.getSign()
        )
        headers = {
            "Referer": "https://my.ruanmei.com/app/user/signin.html?hidemenu=1&appver=2"
        }
        result = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        return result.content

    def signyunrili(self):
        url = (
            self.urlhead
            + "api/usersign/yunrilisign?userHash="
            + self.userhash
            + "&coinHistoryType=160&appver=3.03&platform=windows"
            + self.getSign()
        )
        headers = {
            "Referer": "https://my.ruanmei.com/app/user/signin.html?hidemenu=1&appver=2"
        }
        result = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        return result.content

    def signyunriliAndroid(self):
        url = (
            self.urlhead
            + "api/usersign/yunrilisign?userHash="
            + self.userhash
            + "&coinHistoryType=159"
            + self.getSign()
        )
        headers = {
            "Referer": "https://my.ruanmei.com/app/user/signinyunrili.html?from=mytime_android"
        }
        result = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        return result.content


# ══════════════════ 推送 ══════════════════

def push_sign_result(title: str, msg: str) -> bool:
    """推送签到结果到 shangguan 接口（失败不影响主流程）"""
    if not PUSH_ENABLED:
        print("[推送] 已通过 ITHOME_PUSH=0 关闭")
        return False

    form = urllib.parse.urlencode({"title": title, "msg": msg}).encode("utf-8")
    req = urllib.request.Request(
        PUSH_URL,
        data=form,
        headers={
            "User-Agent": "ithome-sign/1.1",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            print(f"[推送] HTTP {resp.status}: {body[:200]}")
            return 200 <= resp.status < 300
    except Exception as e:
        print(f"[推送] 失败: {e}")
        return False


def build_summary(results):
    """
    results: [(名称, 响应文本), ...]
    返回 (title, msg, all_success)
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ok_list, fail_list, lines = [], [], []
    for name, text in results:
        cleaned = (text or "").replace("\n", " ").strip()
        if "失败" in cleaned:
            fail_list.append(name)
            lines.append(f"❌ 【{name}】{cleaned[:120]}")
        else:
            ok_list.append(name)
            lines.append(f"✅ 【{name}】{cleaned[:120]}")

    total = len(results)
    all_success = len(fail_list) == 0

    if all_success:
        title = "✅ IT之家 签到全部成功"
        head = f"时间：{now}\n状态：{len(ok_list)}/{total} 全部成功"
    else:
        title = f"⚠️ IT之家 签到部分失败（{len(fail_list)}/{total}）"
        head = (
            f"时间：{now}\n"
            f"成功：{len(ok_list)}/{total} → {'、'.join(ok_list) or '无'}\n"
            f"失败：{len(fail_list)}/{total} → {'、'.join(fail_list)}"
        )

    msg = head + "\n" + "=" * 30 + "\n" + "\n".join(lines)
    return title, msg, all_success


# ══════════════════ 入口 ══════════════════

if __name__ == "__main__":
    print("Start IThome sign.")
    print(f"[配置] USERHASH={'已配置' if USERHASH and USERHASH != 'sign' else '未配置(占位)'}")
    print(f"[配置] PUSH_ENABLED={PUSH_ENABLED}")

    ithome = ITHomeSign(USERHASH)
    results = []

    def run(name, func):
        try:
            text = cn(func())
        except Exception as e:
            text = f"请求异常：{e}"
        print(text)
        results.append((name, text))
        return text

    sign_text = run("普通签到", ithome.sign)
    run("lapin签到", ithome.signlapin)
    run("云日历Windows", ithome.signyunrili)
    run("云日历Android", ithome.signyunriliAndroid)

    title, msg, all_success = build_summary(results)
    push_sign_result(title, msg)

    print("签到全部成功" if all_success else "签到存在失败项")
    # 退出码永远 0：单次接口失败不应让 GitHub Actions 标红
    raise SystemExit(0)
