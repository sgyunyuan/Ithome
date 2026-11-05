# encoding:utf-8
"""
@author: zixing
@update: 2026-11-05
@desc: IT之家签到 - 精简优化版（仅保留拉普兰签到）
@ref: https://github.com/daimiaopeng/IthomeQianDao
"""

import binascii
import json
import logging
import re
import time
from datetime import datetime
from os import environ as ENV

import requests
from pyDes import des, ECB

requests.packages.urllib3.disable_warnings()

# ======================
# 日志配置
# ======================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ======================
# 常量配置
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


# ======================
# DES 工具
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
# 签名生成
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
        """生成签名参数"""
        now = int(time.time() * 1000)
        k3 = SignGenerator.gen_key_fragment(now, 3)
        k8 = SignGenerator.gen_key_fragment(now, 8)
        sign_key = "k" + DesUtil.encrypt(k3, k8)
        sign_val = DesUtil.encrypt(
            datetime.fromtimestamp(now / 1000).strftime("%Y-%m-%d %H:%M:%S"), k8
        )
        return f"&timestamp={now}&{sign_key}={sign_val}"


# ======================
# 登录 & 签到
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
        """通过账号密码登录获取 userHash"""
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
        """
        执行签到
        :param sign_type: 0=普通IT之家, 1=拉普兰, 其他=废弃渠道
        """
        endt = SignGenerator.get_sign()
        url = (
            f"{Config.BASE_URL}/api/usersign/sign"
            f"?userHash={self.user_hash}&type={sign_type}{endt}"
        )
        resp = self.session.get(url, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def sign_all(self) -> list:
        """
        依次尝试多个签到渠道
        当前仅保留 type=1（拉普兰），type=0 已下线
        """
        results = []
        # 只保留拉普兰签到（type=1）
        # 普通签到（type=0）因账号系统调整已下线
        for sign_type in [1]:
            try:
                result = self.sign(sign_type)
                results.append({
                    "type": sign_type,
                    "type_name": "拉普兰" if sign_type == 1 else f"type={sign_type}",
                    "success": "失败" not in str(result.get("msg", "")),
                    "result": result,
                })
                logger.info("签到 type=%d: %s", sign_type, result)
            except Exception as e:
                results.append({
                    "type": sign_type,
                    "type_name": "拉普兰" if sign_type == 1 else f"type={sign_type}",
                    "success": False,
                    "result": {"error": str(e)},
                })
                logger.error("签到 type=%d 异常: %s", sign_type, e)
        return results


# ======================
# 主程序
# ======================
def main():
    errors = []

    try:
        if ENV.get("USERHASH"):
            logger.info("使用 USERHASH 签到")
            signer = ITHomeSigner(ENV["USERHASH"])
        elif ENV.get("USERNAME") and ENV.get("PASSWORD"):
            logger.info("使用账号密码登录: %s", ENV["USERNAME"])
            signer = ITHomeSigner.from_credentials(ENV["USERNAME"], ENV["PASSWORD"])
        else:
            raise EnvironmentError(
                "请配置环境变量 USERNAME + PASSWORD，或 USERHASH"
            )

        results = signer.sign_all()

        # 汇总
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

    if errors:
        raise SystemExit(f"签到失败: {'; '.join(errors)}")


if __name__ == "__main__":
    main()
