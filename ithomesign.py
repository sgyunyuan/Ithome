# encoding:utf-8
"""
@author: zixing
@update: 2026-11-05
@desc: IT之家签到 + 结果推送（仅保留拉普兰签到）
"""

import binascii
import json
import logging
import os
import re
import time
from datetime import datetime

import requests
from pyDes import des, ECB

requests.packages.urllib3.disable_warnings()

# ======================
# 日志
# ======================
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ======================
# 配置
# ======================
class Config:
    BASE_URL = "https://my.ruanmei.com"
    DES_KEY = "+f/1+hfh"
    SECRET_STRING = (
        "hd7%b4f8p9)*fd4h5l6|)123/*-+!#$@%^*()_+?>?njidfds[]rfbcvnb3rz/ird|opqqy"
        "h487874515/%90hggigadfihklhkopjj`b3hsdfdsf84215456fi15451%q(#@Fzd795hn"
        "^Ccl$vK^L%#w$^yr%ETvX#0TaPSRm5)OeG)^fQnn6^%^UTtJI#3EZ@p6^Rf$^!O$(jnkOiB"
        "jn3#inhOQQ!aTX8R)9O%#o3zCVxo3tLyVorwYwA^$%^b9Yy$opSEAOOlFBsS^5d^HoF%tJ"
        "$dx%3)^q^c^$al%b4I)QHq^#^AlcK^KZFYf81#bL$n@$%j^H(%m^"
    )
    USER_AGENT = (
        "Mozilla/5.0 (Linux; Android 9; MI 6 Build/PKQ1.190118.001; wv) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
        "Chrome/81.0.4044.138 Mobile Safari/537.36 ithome/rmsdklevel2/night/7.26"
    )

    # 推送配置
    PUSH_URL = os.environ.get("ITHOME_PUSH_URL", "https://api.chuckfang.com/shangguan/")
    PUSH_ENABLED = os.environ.get("ITHOME_PUSH", "1") == "1"
    PUSH_METHOD = "JSON"          # "JSON" | "GET"
    PUSH_FIELD_TITLE = "title"
    PUSH_FIELD_CONTENT = "content"
    PUSH_TIMEOUT = 10
    PUSH_RETRIES = 2
    PUSH_RETRY_INTERVAL = 3


# ======================
# DES
# ======================
class DesUtil:
    @staticmethod
    def pad_zero(data: str) -> str:
        pad_len = 8 - len(data) % 8
        return data + chr(0) * pad_len

    @staticmethod
    def encrypt(data: str, key: str) -> str:
        k = des(key, ECB, key, pad=None)
        encrypted = k.encrypt(DesUtil.pad_zero(data).encode("utf-8"))
        return binascii.b2a_hex(encrypted).decode("utf-8")


# ======================
# 签名
# ======================
class SignGenerator:
    @staticmethod
    def day_of_month(ts: int) -> int:
        return datetime.fromtimestamp(ts / 1000).day

    @staticmethod
    def gen_key_fragment(ts: int, length: int) -> str:
        day = SignGenerator.day_of_month(ts)
        base = round(ts / 0xC350) * day * 3
        secret = Config.SECRET_STRING

        if length == 3:
            indices = [
                base % 0x2710 // 0x3E8,
                base % 0x3E8 // 0x64,
                base % 0x64 // 0xA,
            ]
        elif length == 8:
            indices = [
                base % 0x5F5E100 // 0x989680,
                base % 0x989680 // 0xF4240,
                base % 0xF4240 // 0x186A0,
                base % 0x186A0 // 0x2710,
                base % 0x2710 // 0x3E8,
                base % 0x3E8 // 0x64,
                base % 0x64 // 0xA,
                base % 0xA,
            ]
        else:
            return ""

        return "".join(secret[int(i) * day] for i in indices)

    @staticmethod
    def get_sign() -> str:
        now = int(time.time() * 1000)
        k3 = SignGenerator.gen_key_fragment(now, 3)
        k8 = SignGenerator.gen_key_fragment(now, 8)
        sign_key = "k" + DesUtil.encrypt(k3, k8)
        sign_val = DesUtil.encrypt(
            datetime.fromtimestamp(now / 1000).strftime("%Y-%m-%d %H:%M:%S"), k8
        )
        return f"&timestamp={now}&{sign_key}={sign_val}"


# ======================
# 推送模块
# ======================
class PushSender:
    @staticmethod
    def send(title: str, content: str) -> tuple[bool, str]:
        if not Config.PUSH_ENABLED:
            logger.info("推送已禁用（ITHOME_PUSH != 1），跳过")
            return True, "disabled"

        if not Config.PUSH_URL:
            logger.warning("未配置推送 URL，跳过")
            return True, "no_url"

        payload = {
            Config.PUSH_FIELD_TITLE: title,
            Config.PUSH_FIELD_CONTENT: content,
        }

        last_err = ""
        for attempt in range(1, Config.PUSH_RETRIES + 1):
            try:
                logger.info("推送尝试 %d/%d → %s", attempt, Config.PUSH_RETRIES, Config.PUSH_URL)

                if Config.PUSH_METHOD == "GET":
                    resp = requests.get(Config.PUSH_URL, params=payload, timeout=Config.PUSH_TIMEOUT)
                else:
                    headers = {"Content-Type": "application/json; charset=utf-8"}
                    resp = requests.post(
                        Config.PUSH_URL,
                        json=payload,
                        headers=headers,
                        timeout=Config.PUSH_TIMEOUT,
                    )

                body = (resp.text or "").strip()[:200]
                logger.info("推送响应: HTTP %d | %s", resp.status_code, body)

                if 200 <= resp.status_code < 300:
                    return True, f"HTTP {resp.status_code}"
                else:
                    last_err = f"HTTP {resp.status_code}: {body}"

            except requests.RequestException as e:
                last_err = f"{type(e).__name__}: {e}"
                logger.warning("推送异常: %s", last_err)

            if attempt < Config.PUSH_RETRIES:
                time.sleep(Config.PUSH_RETRY_INTERVAL)

        return False, last_err


# ======================
# 签到
# ======================
class ITHomeSigner:
    def __init__(self, user_hash: str = ""):
        self.user_hash = user_hash
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "user-agent": Config.USER_AGENT,
            "content-type": "application/x-www-form-urlencoded",
            "accept": "*/*",
            "x-requested-with": "com.ruanmei.ithome",
            "referer": "https://my.ruanmei.com/app/user/signin.html?hidemenu=1&appver=2",
        })

    @classmethod
    def from_credentials(cls, username: str, password: str) -> "ITHomeSigner":
        user_hash = cls._login(username, password)
        logger.info("登录成功，userHash: %s...", user_hash[:16])
        return cls(user_hash)

    @staticmethod
    def _login(username: str, password: str) -> str:
        url = f"{Config.BASE_URL}/Default.aspx/LoginUser"
        data = {"mail": username, "psw": password, "rememberme": "true"}
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json; charset=UTF-8",
            "Host": "my.ruanmei.com",
            "Origin": "http://my.ruanmei.com",
            "Referer": "http://my.ruanmei.com/",
            "User-Agent": Config.USER_AGENT,
            "X-Requested-With": "XMLHttpRequest",
        }
        resp = requests.post(url, data=json.dumps(data), headers=headers, timeout=15)
        resp.raise_for_status()
        cookie = resp.headers.get("Set-Cookie", "")
        match = re.search(r"user=hash=([a-zA-Z0-9]+)", cookie)
        if not match:
            raise ValueError("登录失败：无法获取 userHash，可能账号或密码错误")
        return match.group(1)

    def sign(self, sign_type: int = 1) -> dict:
        endt = SignGenerator.get_sign()
        url = (
            f"{Config.BASE_URL}/api/usersign/sign"
            f"?userHash={self.user_hash}&type={sign_type}{endt}"
        )
        resp = self.session.get(url, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def sign_all(self) -> list:
        results = []
        for sign_type in [1]:   # 仅拉普兰
            try:
                result = self.sign(sign_type)
                msg = result.get("msg", "")
                ok = "失败" not in msg
                results.append({
                    "type": sign_type,
                    "type_name": "拉普兰",
                    "success": ok,
                    "result": result,
                })
                logger.info("签到 %s: %s", "拉普兰" if sign_type == 1 else sign_type, result)
            except Exception as e:
                results.append({
                    "type": sign_type,
                    "type_name": "拉普兰",
                    "success": False,
                    "result": {"error": str(e)},
                })
                logger.error("签到异常: %s", e)
        return results


# ======================
# 主程序
# ======================
def main():
    results = []
    errors = []

    try:
        user_hash = os.environ.get("ITHOME_USERHASH", "")
        username = os.environ.get("USERNAME", "")
        password = os.environ.get("PASSWORD", "")

        if user_hash:
            logger.info("使用 USERHASH 签到")
            signer = ITHomeSigner(user_hash)
        elif username and password:
            logger.info("使用账号密码登录: %s", username)
            signer = ITHomeSigner.from_credentials(username, password)
        else:
            raise EnvironmentError("请配置环境变量 ITHOME_USERHASH 或 USERNAME+PASSWORD")

        results = signer.sign_all()

        success_count = sum(1 for r in results if r["success"])
        total = len(results)
        logger.info("签到完成: %d/%d 成功", success_count, total)

        for r in results:
            status = "✅" if r["success"] else "❌"
            logger.info("  %s %s: %s", status, r["type_name"], r["result"])

        if success_count == 0 and total > 0:
            errors.append("所有签到渠道均失败")

    except Exception as e:
        logger.exception("执行异常")
        errors.append(str(e))

    # ---- 推送 ----
    success_count = sum(1 for r in results if r["success"])
    total = len(results)

    if total > 0:
        if success_count == total:
            flag = "全部成功"
        elif success_count == 0:
            flag = "全部失败"
        else:
            flag = "部分成功"

        title = f"IT之家签到 · {flag} {success_count}/{total}"
    else:
        title = "IT之家签到 · 未执行"

    # 排版内容
    lines = [f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"]
    lines.append("─" * 24)
    for r in results:
        mark = "✅" if r["success"] else "❌"
        lines.append(f"{mark} {r['type_name']:<8} {r['result']}")
    if errors:
        lines.append("─" * 24)
        for e in errors:
            lines.append(f"⚠ {e}")
    content = "\n".join(lines)

    logger.info("推送内容:\n%s", content)
    ok, msg = PushSender.send(title, content)
    if ok:
        logger.info("推送成功: %s", msg)
    else:
        logger.warning("推送失败: %s", msg)

    # 最终退出码
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
