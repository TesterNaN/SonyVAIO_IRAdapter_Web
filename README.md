# VGP-URM10 · 纯 WebUSB 红外万能遥控器

索尼 VAIO 的 **VGP-URM10** USB 红外适配器（`VID_054C / PID_0883`）的纯浏览器遥控器。
不需要装索尼那套老应用，**Chrome / Edge 打开本页就能用** —— 协议是逆向出来的，码库是从
UEI QuickSet 数据库里导出来的（3661 个码表编号）。

## 用法

1. **必须用 Chrome 或 Edge**（WebUSB 只有它们认），并且必须是 **https 或 localhost**：
   - 托管在 GitHub Pages 上时打开 `https://<你的用户名>.github.io/<仓库名>/` 即可；
   - 本机也可以用 `python -m http.server` 起一个，然后开 `http://localhost:8000/`。
2. **Windows 需要装一次 Sony 原厂驱动安装包**：WebUSB 要求设备由系统自带的通用驱动
   `winusb.sys` 接管，而这个设备没有在描述符里自我声明 WinUSB，所以干净的 Windows 不会自动绑定。
   - 点页面右上角「找不到设备？」→ 点那个按钮下载 `Sony_IR_driver_EP0000311568.exe`，
     运行它、按提示装完；
   - 把适配器**拔插一次**，刷新页面，点「连接设备」；
   - 验证：`Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB\VID_054C&PID_0883\*' | Select Service`
     应显示 `Service : WINUSB`。
   - 为什么不用自制 INF：x64 Windows 会拒（"第三方 INF 不包含数字签名信息"），
     原厂包的 `sird.cat` 是 WHQL 签名的，而且在 Win8.1+ 上绑的正是 WinUSB。
3. 页面上选一台遥控器（左边可按品牌/型号搜码库并「装机到设备」），右边直接按。

## 注意

* **适配器插在谁身上，就只能由那台机器的浏览器操作它。** WebUSB 是独占访问，
  一台电脑同一条命令通道一次只处理一条命令；手机/另一台电脑打开同一个网址**不能**替这台机器发红外
  （而且非 https 的地址根本拿不到 WebUSB）。
* 同一个页面一次只能占用一个适配器；多个适配器请各开一个页面/标签。
* 按一下大约 150ms —— 设备要先把整段红外发完才回应，不是卡。
* 连续快速点击会自动排队（最多 10 下），超出的会明确提示"丢掉一次"。

## 它是怎么工作的（简述）

| 层 | 内容 |
|---|---|
| 传输 | WebUSB：OUT 管道写命令帧，IN 管道读回应 |
| 命令 | `40 41 42 43 | len | type | …`，每条命令前先写 1 字节 `00` 解锁，**必须串行** |
| 码表 | profile ID = 码表编号（T 类 +0x0000、C +0x1000、N +0x2000、M/R +0x7000、A +0x8000…） |
| 版面 | 按键位置/语义来自官方应用的 XAML（键号 = `x:Name="locationNN"`） |

详细逆向记录（协议逐字节、48 个实测结论、踩过的坑）见 `REPORT.md`（如果用 `--with-report` 打包了）。

本页数据文件都是明文 JSON/BIN，直接 `view-source` 就能看，不需要后端。
