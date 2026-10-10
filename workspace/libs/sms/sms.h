/*
 * SMS 验证码发送模块 - 动态库接口头文件
 * 封装阿里云短信服务 API 调用（签名、发送请求、响应解析）
 *
 * 编译: gcc -shared -fPIC -o libsms.so sms.c -lcurl -lssl -lcrypto
 * 安装路径: /usr/local/lib/libsms.so 或 /home/workspace/sms/libsms.so
 */

#ifndef SMS_H
#define SMS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 初始化短信模块
 * @param config_path 配置文件路径（如 /etc/sms_config.ini）
 * @return 0成功，-1失败（凭证错误或curl初始化失败）
 */
int sms_init(const char *config_path);

/**
 * 发送短信验证码
 * @param phone 手机号（需包含国际区号，如 +8613800138000）
 * @param code  6位验证码字符串
 * @return 0成功，-1参数错误，-2网络超时，-3阿里云接口返回错误（余额不足/模板不匹配等）
 */
int sms_send_code(const char *phone, const char *code);

/**
 * 验证短信验证码
 * @param phone 手机号
 * @param code  用户输入的验证码
 * @return 0验证通过，-1参数/脚本错误，-2验证不匹配
 */
int sms_verify_code(const char *phone, const char *code);

/**
 * 释放资源
 */
void sms_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* SMS_H */
