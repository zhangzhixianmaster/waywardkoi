# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import random
from typing import List
from collections import defaultdict

from alibabacloud_dypnsapi20170525.client import Client as Dypnsapi20170525Client
from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_credentials.models import Config as CredentialConfig
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_dypnsapi20170525 import models as dypnsapi_20170525_models
from alibabacloud_tea_util import models as util_models

# ============ 配置文件路径 ============
CONFIG_FILE = "/etc/sms.conf"

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("ERROR: 配置文件未找到，请检查路径")
        sys.exit(1)
    except json.JSONDecodeError:
        print("ERROR: 配置文件格式错误")
        sys.exit(1)

# ============ 加载配置 ============
config_data = load_config()
ACCESS_KEY_ID = config_data.get('access_key_id')
ACCESS_KEY_SECRET = config_data.get('access_key_secret')
SIGN_NAME = config_data.get('sign_name', '速通互联验证码')
TEMPLATE_CODE = config_data.get('template_code', '100001')

# ============ 限流配置 ============
CONFIG = {
    "sign_name": SIGN_NAME,
    "template_code": TEMPLATE_CODE,
    "send_interval": 60,
    "daily_max": 10,
    "max_fail_attempts": 3,
    "fail_lock_duration": 300,
    "http_timeout": 5000
}

# ============ 限流状态存储 ============
state = {
    "last_send_time": {},
    "daily_count": defaultdict(int),
    "fail_attempts": defaultdict(int)
}

def check_rate_limit(phone: str):
    current_time = time.time()
    if phone in state.get("lock_until", {}) and current_time < state["lock_until"][phone]:
        return False, f"账号已锁定，请{int(state['lock_until'][phone] - current_time)}秒后重试"
    if phone in state["last_send_time"]:
        elapsed = current_time - state["last_send_time"][phone]
        if elapsed < CONFIG["send_interval"]:
            return False, f"发送过于频繁，请{int(CONFIG['send_interval'] - elapsed)}秒后重试"
    if state["daily_count"][phone] >= CONFIG["daily_max"]:
        return False, "今日发送次数已达上限"
    return True, "OK"

def update_state_after_send(phone: str, success: bool):
    current_time = time.time()
    state["last_send_time"][phone] = current_time
    if success:
        state["fail_attempts"][phone] = 0
        state["daily_count"][phone] += 1
        if phone in state.get("lock_until", {}):
            del state["lock_until"][phone]
    else:
        state["fail_attempts"][phone] += 1
        if state["fail_attempts"][phone] >= CONFIG["max_fail_attempts"]:
            state["lock_until"][phone] = current_time + CONFIG["fail_lock_duration"]

class Sample:
    @staticmethod
    def create_client():
        """使用配置文件中的 AccessKey 创建客户端"""
        if not ACCESS_KEY_ID or not ACCESS_KEY_SECRET:
            raise Exception("配置文件中 access_key_id 或 access_key_secret 为空")
        credential_config = CredentialConfig(
            type='access_key',
            access_key_id=ACCESS_KEY_ID,
            access_key_secret=ACCESS_KEY_SECRET
        )
        credential = CredentialClient(credential_config)
        config = open_api_models.Config(credential=credential)
        config.endpoint = 'dypnsapi.aliyuncs.com'
        return Dypnsapi20170525Client(config)

    @staticmethod
    def main(args: List[str]):
        if len(args) < 1:
            print("ERROR: Missing phone number")
            sys.exit(1)
        phone_number = args[0]

        # 限流检查
        allowed, msg = check_rate_limit(phone_number)
        if not allowed:
            print(f"ERROR: {msg}")
            sys.exit(1)

        client = Sample.create_client()
        # 关键：使用占位符 ##code##，让阿里云系统自动生成验证码
        template_param = json.dumps({"code": "##code##", "min": "6"})
        request = dypnsapi_20170525_models.SendSmsVerifyCodeRequest(
            sign_name=CONFIG["sign_name"],
            template_code=CONFIG["template_code"],
            template_param=template_param,
            phone_number=phone_number
        )
        runtime = util_models.RuntimeOptions()
        runtime.connect_timeout = CONFIG["http_timeout"]

        try:
            resp = client.send_sms_verify_code_with_options(request, runtime)
            resp_body = resp.body
            if hasattr(resp_body, 'code') and resp_body.code == 'OK':
                update_state_after_send(phone_number, success=True)
                # 发送成功，返回成功状态（验证码已发送到用户手机）
                print(json.dumps({"status": "success", "request_id": getattr(resp_body, 'request_id', '')}))
            else:
                update_state_after_send(phone_number, success=False)
                err_code = getattr(resp_body, 'code', 'unknown')
                err_msg = getattr(resp_body, 'message', '')
                print(f"ERROR: API Return {err_code} - {err_msg}")
        except Exception as error:
            update_state_after_send(phone_number, success=False)
            print(f"ERROR: {error.message}")

if __name__ == '__main__':
    Sample.main(sys.argv[1:])