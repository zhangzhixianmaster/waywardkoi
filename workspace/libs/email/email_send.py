# -*- coding: utf-8 -*-
# 邮件验证码发送 - 阿里云 DirectMail
# 调用方式: python email_send.py <email> <code>

import os
import sys
import json
from alibabacloud_dm20151123.client import Client as DmClient
from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_credentials.models import Config as CredentialConfig
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_dm20151123 import models as dm_models
from alibabacloud_tea_util import models as util_models

CONFIG_FILE = "/etc/sms.conf"

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        print(json.dumps({"status": "error", "msg": "配置文件未找到"}))
        sys.exit(1)

config_data = load_config()
ACCESS_KEY_ID = config_data.get('access_key_id', '')
ACCESS_KEY_SECRET = config_data.get('access_key_secret', '')
FROM_ADDRESS = config_data.get('from_address', 'notice@mail.yourdomain.com')
FROM_ALIAS = config_data.get('from_alias', 'IoT Platform')
SUBJECT = config_data.get('subject', 'IoT Platform 登录验证码')
TEMPLATE_TAG = config_data.get('email_tag_name', 'code')

def main():
    if len(sys.argv) < 3:
        print(json.dumps({"status": "error", "msg": "缺少参数: email code"}))
        sys.exit(1)

    to_address = sys.argv[1]
    code = sys.argv[2]

    credential_config = CredentialConfig(
        type='access_key',
        access_key_id=ACCESS_KEY_ID,
        access_key_secret=ACCESS_KEY_SECRET
    )
    credential = CredentialClient(credential_config)
    config = open_api_models.Config(credential=credential)
    config.endpoint = 'dm.aliyuncs.com'
    client = DmClient(config)

    request = dm_models.SingleSendMailRequest(
        account_name=FROM_ADDRESS,
        from_alias=FROM_ALIAS,
        address_type=1,
        reply_to_address='true',
        to_address=to_address,
        subject=SUBJECT,
        html_body='<p>您的验证码是: <strong>' + code + '</strong>，' + '5分钟内有效</p>'
    )
    runtime = util_models.RuntimeOptions()
    runtime.connect_timeout = 8000

    try:
        resp = client.single_send_mail_with_options(request, runtime)
        resp_body = resp.body
        if hasattr(resp_body, 'request_id'):
            print(json.dumps({"status": "success", "request_id": resp_body.request_id}))
        else:
            print(json.dumps({"status": "success"}))
    except Exception as error:
        print(json.dumps({"status": "error", "msg": str(error)}))

if __name__ == '__main__':
    main()
