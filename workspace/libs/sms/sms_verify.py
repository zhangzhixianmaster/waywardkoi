# -*- coding: utf-8 -*-
# 短信验证码校验
# 调用方式: python sms_verify.py <phone> <code>

import os
import sys
import json
from typing import List

from alibabacloud_dypnsapi20170525.client import Client as Dypnsapi20170525Client
from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_credentials.models import Config as CredentialConfig
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_dypnsapi20170525 import models as dypnsapi_20170525_models
from alibabacloud_tea_util import models as util_models

CONFIG_FILE = "/etc/sms.conf"

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(json.dumps({"status": "error", "msg": "配置文件未找到"}))
        sys.exit(1)
    except json.JSONDecodeError:
        print(json.dumps({"status": "error", "msg": "配置文件格式错误"}))
        sys.exit(1)

config_data = load_config()
ACCESS_KEY_ID = config_data.get('access_key_id')
ACCESS_KEY_SECRET = config_data.get('access_key_secret')

def create_client():
    if not ACCESS_KEY_ID or not ACCESS_KEY_SECRET:
        raise Exception("配置文件中 access_key 缺失")
    credential_config = CredentialConfig(
        type='access_key',
        access_key_id=ACCESS_KEY_ID,
        access_key_secret=ACCESS_KEY_SECRET
    )
    credential = CredentialClient(credential_config)
    config = open_api_models.Config(credential=credential)
    config.endpoint = 'dypnsapi.aliyuncs.com'
    return Dypnsapi20170525Client(config)

def main():
    if len(sys.argv) < 3:
        print(json.dumps({"status": "error", "msg": "缺少参数: phone code"}))
        sys.exit(1)

    phone = sys.argv[1]
    code = sys.argv[2]

    client = create_client()
    request = dypnsapi_20170525_models.CheckSmsVerifyCodeRequest(
        phone_number=phone,
        verify_code=code
    )
    runtime = util_models.RuntimeOptions()
    runtime.connect_timeout = 5000
    runtime.read_timeout = 10000

    try:
        resp = client.check_sms_verify_code_with_options(request, runtime)
        resp_body = resp.body

        # 打印完整属性（调试）
        print(json.dumps({
            "debug": "full_response_attributes",
            "attributes": resp_body.__dict__ if hasattr(resp_body, '__dict__') else str(resp_body)
        }, default=str, indent=2))

        # 尝试多种方式获取核验结果
        verify_result = None
        # 尝试直接字段
        if hasattr(resp_body, 'VerifyResult'):
            verify_result = resp_body.VerifyResult
        elif hasattr(resp_body, 'verify_result'):
            verify_result = resp_body.verify_result
        # 尝试从 model 中获取
        if verify_result is None and hasattr(resp_body, 'model'):
            model = resp_body.model
            if hasattr(model, 'VerifyResult'):
                verify_result = model.VerifyResult
            elif hasattr(model, 'verify_result'):
                verify_result = model.verify_result

        if hasattr(resp_body, 'code') and resp_body.code == 'OK':
            if verify_result == 'PASS':
                print(json.dumps({
                    "status": "success",
                    "request_id": getattr(resp_body, 'request_id', ''),
                    "msg": "验证通过"
                }))
            else:
                print(json.dumps({
                    "status": "fail",
                    "msg": "验证码无效或已过期",
                    "detail": verify_result,
                    "request_id": getattr(resp_body, 'request_id', '')
                }))
        else:
            print(json.dumps({
                "status": "error",
                "code": getattr(resp_body, 'code', 'unknown'),
                "msg": getattr(resp_body, 'message', ''),
                "request_id": getattr(resp_body, 'request_id', '')
            }))
    except Exception as error:
        print(json.dumps({"status": "error", "msg": str(error)}))

if __name__ == '__main__':
    main()