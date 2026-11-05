# encoding: utf-8
"""
IT之家签到 - 仅拉普兰 (type=1)
已移除推送模块，仅保留签到核心逻辑
"""
import binascii
import json
import logging
import os
import time
from datetime import datetime

import requests
from pyDes import des, ECB

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ithome")


class Config:
    BASE = "https://my.ruanmei.com"
    DES_KEY = "+f/1+hfh"
    UA = (
        "Mozilla/5.0 (Linux; Android 9; MI 6 Build/PKQ1.190118.001; wv) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
        "Chrome/81.0.4044.138 Mobile Safari/537.36 ithome/rmsdklevel2/night/7.26"
    )


class DesUtil:
    @staticmethod
    def pad(s: str) -> str:
        return s + chr(0) * (8 - len(s) % 8)

    @staticmethod
    def enc(s: str, key: str) -> str:
        k = des(key, ECB, key, pad=None)
        return binascii.b2a_hex(k.encrypt(DesUtil.pad(s).encode())).decode()


class SignMaker:
    SECRET = (
        "hd7%b4f8p9)*fd4h5l6|)123/*-+!#$@%^*()_+?>?njidfds[]rfbcvnb3rz/ird|opqqy"
        "h487874515/%90hggigadfihklhkopjj`b3hsdfdsf84215456fi15451%q(#@Fzd795hn"
        "^Ccl$vK^L%#w$^yr%ETvX#0TaPSRm5)OeG)^fQnn6^%^UTtJI#3EZ@p6^Rf$^!O$(jnkOiB"
        "jn3#inhOQQ!aTX8R)9O%#o3zCVxo3tLyVorwYwA^$%^b9Yy$opSEAOOlFBsS^5d^HoF%tJ"
        "$dx%3)^q^c^$al%b4I)QHq^#^AlcK^KZFYf81#bL$n@$%j^H(%m^"
    )

    @staticmethod
    def frag(ts: int, length: int) -> str:
        day = datetime.fromtimestamp(ts / 1000).day
        base = round(ts / 50000) * day * 3
        if length == 3:
            idx = [base % 10000 // 1000, base % 1000 // 100, base % 100 // 10]
        else:
            idx = [
                base % 100000000 // 10000000,
                base % 10000000 // 1000000,
                base % 1000000 // 100000,
                base % 100000 // 10000,
                base % 10000 // 1000,
                base % 1000 // 100,
                base % 100 // 10,
                base % 10,
            ]
        return "".join(SignMaker.SECRET[int(i) * day] for i in idx)

    @staticmethod
    def make() -> str:
        now = int(time.time() * 1000)
        k3 = SignMaker.frag(now, 3)
        k8 = SignMaker.frag(now, 8)
        sign_key = "k" + DesUtil.enc(k3, k8)
        sign_val = DesUtil.enc(
            datetime.fromtimestamp(now / 1000).strftime("%Y-%m-%d %H:%M:%S"), k8
        )
        return f"&timestamp={now}&{sign_key}={sign_val}"


class Signer:
    def __init__(self, user_hash: str):
        self.hash = user_hash
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers.update({
            "user-agent": Config.UA,
            "content-type": "application/x-www-form-urlencoded",
            "x-requested-with": "com.ruanmei.ithome",
        })

    @classmethod
    def login(cls, user, pwd):
        url = f"{Config.BASE}/Default.aspx/LoginUser"
        data = {"mail": user, "psw": pwd, "rememberme": "true"}
        h = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json; charset=UTF-8",
            "Referer": "http://my.ruanmei.com/",
            "User-Agent": Config.UA,
            "X-Requested-With": "XMLHttpRequest",
        }
        r = requests.post(url, data=json.dumps(data), headers=h, timeout=15)
        r.raise_for_status()
        cookie = r.headers.get("Set-Cookie", "")
        m = __import__("re").search(r"user=hash=([a-zA-Z0-9]+)", cookie)
        if not m:
            raise RuntimeError("登录失败，账号或密码错误")
        logger.info("登录成功，userHash: %s...", m.group(1)[:16])
        return cls(m.group(1))

    def do_sign(self, t: int = 1) -> dict:
        url = f"{Config.BASE}/api/usersign/sign?userHash={self.hash}&type={t}{SignMaker.make()}"
        r = self.s.get(url, timeout=15)
        r.raise_for_status()
        return r.json()


def main():
    user_hash = os.environ.get("ITHOME_USERHASH", "").strip()
    user = os.environ.get("USERNAME", "").strip()
    pwd = os.environ.get("PASSWORD", "").strip()

    # 凭证检查
    if not user_hash and not (user and pwd):
        logger.error("❌ 未配置凭证：请设置 ITHOME_USERHASH 或 USERNAME+PASSWORD")
        raise SystemExit(1)

    # 初始化签到器
    if user_hash:
        logger.info("使用 USERHASH 签到")
        signer = Signer(user_hash)
    else:
        logger.info("使用账号密码登录: %s", user)
        signer = Signer.login(user, pwd)

    # 执行签到（仅拉普兰 type=1）
    logger.info("开始签到...")
    try:
        res = signer.do_sign(1)
        msg = res.get("msg", "")
        ok = "失败" not in msg

        if ok:
            logger.info("✅ 拉普兰签到成功 | %s", msg)
        else:
            logger.warning("❌ 拉普兰签到失败 | %s", msg)

        if not ok:
            raise SystemExit(1)

    except Exception as e:
        logger.exception("签到异常")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
