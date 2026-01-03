# 2FA (TOTP) Python Demo

这个 demo 演示完整 2FA（TOTP）链路：

1. 生成 2FA 凭证（Base32 secret）并保存到 `totp_credential.json`
2. 生成 `otpauth://...` provisioning URI
3. 把 URI 编码成二维码并保存为一张图片 `totp_qr.png`
4. 用代码从二维码图片“扫码”解码回 URI（模拟手机扫码拿到 secret）
5. 使用解码出的 secret 生成 6 位动态码，并与本地存储的 secret 生成的动态码对比
6. 随机一个时间点，生成并验证该时间点的动态码（演示 `for_time` 校验）

## 环境

使用 `uv` 创建虚拟环境：

```powershell
cd d:\Code\Python\2FA
uv venv
uv pip install pyotp qrcode[pil] pillow opencv-python
```

> 本项目用 OpenCV 的 `QRCodeDetector` 解码二维码（避免系统依赖），所以需要 `opencv-python`。

## 运行

1) 初始化：生成凭证 + 生成二维码图片

```powershell
cd d:\Code\Python\2FA
.\.venv\Scripts\python.exe .\demo.py init
```

会生成：
- `totp_credential.json`
- `totp_qr.png`

2) 扫码并对比当前 6 位动态码

```powershell
.\.venv\Scripts\python.exe .\demo.py scan
```

3) 随机时间点校验

```powershell
.\.venv\Scripts\python.exe .\demo.py verify
```

4) 输入手机上的 6 位动态码并验证

```powershell
.\.venv\Scripts\python.exe .\demo.py check
```

也可以直接用参数传入：

```powershell
.\.venv\Scripts\python.exe .\demo.py check --code 123456
```

## 备注

- TOTP 本质：$\text{TOTP} = \text{HOTP}(K, T)$，其中 $T = \lfloor (\text{unixTime} - T_0) / X \rfloor$。
- 常用参数：`digits=6`，`period=30s`，`algorithm=SHA1`。
