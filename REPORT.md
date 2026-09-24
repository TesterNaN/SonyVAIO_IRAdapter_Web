# SIRD.sys 逆向报告 — Sony IR Remote Control (VAIO 内置红外接收器)

> 目标：`SIRD.sys` x64 / x86（Sony IR Remote Control 驱动，2013）
> 方法：PE 静态分析（capstone 反汇编）+ Ghidra 11.4.2 headless 反编译 + 手工核对控制流
> 结论状态：**IOCTL 表 / USB 请求表 / 数据通路 = 已确证**；**每个请求的业务含义 = 由长度与配对关系推测**（驱动内不含任何字符串、结构体符号或 IR 解析代码）

---

## 0. 速览

| 项目 | 结论 |
|---|---|
| 驱动模型 | KMDF（KMDF 1.11，**静态链接**：只导入 `WDFLDR.SYS!WdfVersionBind*`） |
| 设备 ID | `USB\VID_054C&PID_06D9`（Win8.1+ 分支另外支持 `PID_0883`） |
| 实测硬件 | 已用 PID_0883 真机跑通：**"Silicom Labs / IR Adapter"**（序列号 0082BA65）、Full Speed、接口类 0xFF、**2× Bulk 端点 0x01 OUT / 0x82 IN、64 字节包**（借用 Sony VID/PID 的第三方红外适配器，详见 §9） |
| 用户态接口 | 驱动自建设备接口 GUID：`{D9527091-AC8B-4D57-8EC7-CA0790DBCBBD}` <br> INF 为 WinUSB 分支写入的接口 GUID：`{AC2C0F91-97D5-452D-8F89-E055C8C498A4}` |
| 对外命令面 | **28 个自定义 IOCTL**（DeviceType `0xC321`，全部 METHOD_BUFFERED） |
| 数据通路 | **2 条 USB 管道**（一条 IN 读、一条 OUT 写）+ **26 个厂商控制请求** |
| 上报结构 | **没有**。驱动不做 IR 解码、不建环形缓冲、不发 WMI 事件；数据是原始字节直通 |
| 命名规律 | IOCTL function = `0x1800 + bRequest`（设备→主机）/ `0x2800 + bRequest`（主机→设备）；`0x1820`/`0x2821` 保留给管道读/写 |

**最重要的实践结论**：在 Win8.1 / Win10 / Win11 上，INF 的 `[Standard.NTamd64.6.3]` 段生效 → 装的是**系统自带 WinUSB**，`SIRD.sys` 根本不会被加载（详见 §6）。也就是说这套协议完全可以由用户态程序用 WinUSB 直接复现，不需要这份 2013 年的驱动。

---

## 1. 样本与签名

| 文件 | 大小 | SHA256 |
|---|---|---|
| `EP0000311568.exe`（官方自解压包） | 10,995,408 | `DC64D9D040AF54AF60A84293865BE9D34095C0AF509FEC5A1712805A1DAD17EA` |
| `Disk1\x64\SIRD.sys` | 19,968 | `21881B3D1BE1B263E1A84F1C5BB1EA317C28776E78F6853DA973E84E2E8078D5` |
| `Disk1\x86\SIRD.sys` | 16,896 | `D88FB001AD25D397D49C7066A943D8F2B388DB8A449872CFB465A2C71004736C` |
| `Disk1\x64\sird.cat` | 11,018 | `AD98B6A2F81A3AF6612A08B52F6ACC3B16E65382D4609965E04ABD835CEC2B14` |

* 签名：`SIRD.sys` 与 `sird.cat` 均为 **WHQL** 签名（`CN=Microsoft Windows Hardware Compatibility Publisher`，签发者 `Microsoft Windows Third Party Component CA 2012`，时间戳 `Microsoft Time-Stamp Service`，`Get-AuthenticodeSignature` = Valid）。→ Win10/11 仍可正常安装。
* 版本：驱动文件版本 `1.0.0.4240`（编译时间戳 2013-04-24 02:37 UTC），INF `DriverVer=08/21/2013,1.1.0.08210`（INF 比 SYS 新一版，SYS 内容未变）。
* 泄漏的内部路径（x64）：
  `D:\SVN\300IAIS13010_133Q_RemoCon\02.SourceCodeLibrary\3.DevelopLibrary\06.RemoCon\3.Trunk\03.Driver\01.COD\SIRD\x64\Win8Release\SIRD.pdb`
  → 项目代号 `RemoCon`（Remote Control），说明该驱动是索尼多条产品线共用的遥控/红外项目代码。
* 无 PDB 符号可用；驱动内**没有** `DbgPrint` / 字符串表，只有 WPP 追踪（`EtwRegisterClassicProvider` / `WmiTraceMessage`，运行时通过 `MmGetSystemRoutineAddress` 解析，见 `FUN_14000677c`）。

---

## 2. 驱动结构（已确证）

### 2.1 启动链

```
PE entry 0x1400015d0
  └─ FxStubDriverEntryWorker (0x1400014a8)   ← KMDF 静态库绑定（WdfVersionBind / WdfVersionBindClass）
       └─ DriverEntry = FUN_140009008 (INIT)
            ├─ FUN_14000677c   WPP/ETW 初始化
            ├─ FUN_1400066f4   WPP 注册
            └─ WdfDriverCreate(DriverObject, RegistryPath,
                               Attributes{Size=0x38, EvtCleanupCallback=FUN_14000665c,
                                          ExecutionLevel=Passive(1), SynchronizationScope=Device(1)},
                               Config{Size=0x20, EvtDriverDeviceAdd=0x14000664c}, &Driver)
                0x14000664c = mov rcx,rdx ; jmp 0x140006008   ← 设备添加回调 thunk
```

### 2.2 EvtDriverDeviceAdd = `FUN_140006008`

* PnP/电源回调（0x90 字节 `WDF_PNPPOWER_EVENT_CALLBACKS`，`WdfDeviceInitSetPnpPowerEventCallbacks`）：`base+8`、`base+0x18` 都指向空实现 `LAB_140006340`（直接返回成功），`base+0x28` = `FUN_14000634c`（USB 目标初始化）。字段顺序对应到具体回调名（Start / D0Entry / PrepareHardware 之类）不影响协议结论，故不展开。
* `WdfDeviceInitSetExclusive(DeviceInit, WdfUseDefault)`；另一处设备初始化调用带参数 `1`（按 `WDF_DEVICE_IO_TYPE` 推断为 `WdfDeviceIoBuffered`，与后面用 `WdfRequestRetrieve*Memory` 处理缓冲 I/O 的写法一致）
* `WdfDeviceCreate(&DeviceInit, &Attrs{ContextTypeInfo=PTR_DAT_140003118}, &Device)`
* `WdfDeviceCreateDeviceInterface(Device, &{D9527091-AC8B-4D57-8EC7-CA0790DBCBBD}, NULL)`
* 电源策略（`WdfDeviceAssignS0IdleSettings` 等，与协议无关，略）
* 创建 3 个 IO 队列：`FUN_140007de4`
* `IoSetDeviceInterfacePropertyData(...)` 设置接口属性

### 2.3 设备上下文（WDFDEVICE context）

| 偏移 | 内容 | 证据 |
|---|---|---|
| `+0x00` | `WDFUSBDEVICE`（UsbDevice 句柄） | `FUN_14000634c`：`WdfUsbTargetDeviceCreateWithParameters(Device, {Size=8, USBDClientContractVersion=0x602}, NULL, ctx+0)`；后续所有控制请求都用 `ctx[0]` 作为目标 |
| `+0x08` | `WDFUSBINTERFACE`（配置后的接口） | `FUN_1400064d4`：`WdfUsbTargetDeviceSelectConfig` 回填的已配置接口句柄（params+0x10）写入 `ctx[1]`，随后同一值作为 `WdfUsbInterfaceGetConfiguredPipe(ctx[1], i, …)` 的第 1 参数 |
| `+0x10` | 管道句柄（**IN**，读设备） | `FUN_1400064d4` 把第一个 `IsInEndpoint` 为真的管道存这里；`FUN_140001060` 用 `ctx[0x10]` + `WdfRequestRetrieveOutputMemory` + `WdfUsbTargetPipeFormatRequestForRead` → 读管道 |
| `+0x18` | 管道句柄（**OUT**，写设备） | 同上第二个；`FUN_1400011a4` 用 `ctx[0x18]` + `WdfRequestRetrieveInputMemory` + `WdfUsbTargetPipeFormatRequestForWrite` → 写管道 |

### 2.4 USB 初始化 = `FUN_14000634c`

```
ctx = WdfObjectGetTypedContext(Device)
if (ctx == NULL) return STATUS_...
if (ctx->UsbDevice != NULL) return;                       // 只做一次
WdfUsbTargetDeviceCreateWithParameters(Device,
        &{Size=8, USBDClientContractVersion=0x0602}, NULL, &ctx->UsbDevice)
WdfUsbTargetDeviceSelectConfig(ctx->UsbDevice, NULL, &{Size=0x20, Type=3})
FUN_1400064d4(Device)                                     // 枚举管道
```
`FUN_1400064d4`：再做一次 `WdfUsbTargetDeviceSelectConfig(UsbDevice, NULL, &{Size=0x20, Type=2})`，
从回填参数里取出**已配置接口句柄**（存入 `ctx+0x08`）与**管道数量**，然后
`WdfUsbInterfaceGetConfiguredPipe(ctx+0x08, i, &pipeInfo)` 逐个枚举，
`WdfUsbTargetPipeSetNoMaximumPacketSizeCheck(pipe)`，并对 **`pipeInfo.PipeType == 3`** 的管道用
`WdfUsbTargetPipeIsInEndpoint` / `IsOutEndpoint` 分别存入 `ctx+0x10` / `ctx+0x18`。

> ✅ **已用真机确认（PID_0883，本机实测）**：`pipeInfo.PipeType == 3` 就是 **Bulk**（`WDF_USB_PIPE_TYPE: Invalid=0, Control=1, Isochronous=2, Bulk=3, Interrupt=4`）。设备描述符实测：`bNumEndpoints=2`，`07 05 01 02 40 00 00`（EP 0x01 OUT / Bulk / 64）与 `07 05 82 02 40 00 00`（EP 0x82 IN / Bulk / 64），Full Speed，接口类 0xFF/00/00。详见 §9。

### 2.5 队列（`FUN_140007de4`，`WDF_IO_QUEUE_CONFIG` Size=0x60）

| # | DispatchType | 回调 | 注册的请求类型 | 说明 |
|---|---|---|---|---|
| 1 | Parallel(2) | `EvtIoDeviceControl = FUN_140007500`，`EvtIoStop = FUN_140001164` | DefaultQueue=1（默认队列） | **28 个 IOCTL 的分发器** |
| 2 | Sequential(1) | `EvtIoRead = FUN_140001060` | `WdfDeviceConfigureRequestDispatching(...,3)` | 从 IN 管道读 → 写进请求的输出缓冲 |
| 3 | Sequential(1) | `EvtIoWrite = FUN_1400011a4` | `WdfDeviceConfigureRequestDispatching(...,4)` | 请求的输入缓冲 → 写入 OUT 管道 |

即：`ReadFile(设备)`：数据从设备管道流到用户缓冲；`WriteFile(设备)`：用户缓冲写入设备管道。
（第 2/3 个队列只是给这两个回调用顺序语义；IOCTL 之外的读写路径与 IOCTL `0xC3216080` / `0xC321A084` 是同一段代码。）

### 2.6 WMI 只是追踪

`IoWMIRegistrationControl` 仅用于 WPP/ETW classic provider 的注册/注销（`FUN_140006684` / `FUN_1400066f4` / `FUN_140006878`），**与红外数据上报无关**。

---

## 3. IOCTL 全表（28 个，已确证）

分发器：`FUN_140007500` = `EvtIoDeviceControl(Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode)`

* 所有 IOCTL：`DeviceType = 0xC321`，`Method = 0 (METHOD_BUFFERED)`。
* `0xC3216xxx` 组：访问位 = 1，检查 **OutputBufferLength**，用 `WdfRequestRetrieveOutputBuffer` 取缓冲 → 数据由设备送回。
* `0xC321Axxx` 组：访问位 = 2，检查 **InputBufferLength**，用 `WdfRequestRetrieveInputBuffer` 取缓冲 → 内容是发给设备的参数/数据。
* 长度不足 → `STATUS_INVALID_PARAMETER (0xC000000D)`；成功时 `IoStatus.Information` = 实际传输字节数；控制请求的 NTSTATUS 直接作为 IOCTL 的返回状态。
* 传输超时：所有控制请求都带 `WDF_REQUEST_SEND_OPTIONS{Size=0x10, Flags=WDF_REQUEST_SEND_OPTION_TIMEOUT, Timeout=-5s}`（`0xFFFFFFFFFD050F80`）。

### 3.1 设备 → 主机（对应用户态：`DeviceIoControl(h, code, NULL, 0, outBuf, N, ...)`）

| IOCTL | function | 缓冲区需求 | 底层 USB 动作 | 处理函数 |
|---|---|---|---|---|
| `0xC3216008` | 0x1802 | Out ≥ 2 | vendor IN，`bRequest=0x02`，读 2 字节 | `FUN_140006cb0` |
| `0xC3216010` | 0x1804 | Out ≥ 2 | vendor IN，`0x04`，2 字节 | `FUN_140007174` |
| `0xC3216020` | 0x1808 | Out ≥ 1 | vendor IN，`0x08`，1 字节 | `FUN_140007240` |
| `0xC3216030` | 0x180C | Out ≥ 2 | vendor IN，`0x0C`，2 字节 | `FUN_140006f14` |
| `0xC3216038` | 0x180E | Out ≥ 6 | vendor IN，`0x0E`，6 字节 | `FUN_140006d7c` |
| `0xC321603C` | 0x180F | Out ≥ 256 | vendor IN，`0x0F`，256 字节 | `FUN_140007308` |
| `0xC3216040` | 0x1810 | Out ≥ 19 | vendor IN，`0x10`，19 字节 | `FUN_140006e48` |
| `0xC3216050` | 0x1814 | Out ≥ 16 | vendor IN，`0x14`，16 字节 | `FUN_1400070ac` |
| `0xC3216058` | 0x1816 | Out ≥ 2 | vendor IN，`0x16`，2 字节 | `FUN_140006fe0` |
| `0xC3216074` | 0x181D | Out ≥ 4 | vendor IN，`0x1D`，4 字节 | `FUN_140006be4` |
| `0xC3216080` | 0x1820 | 任意（=读取字节数） | **读 IN 管道 → 输出缓冲**，异步完成 | `FUN_140001060` |

### 3.2 主机 → 设备（对应用户态：`DeviceIoControl(h, code, inBuf, N, NULL, 0, ...)`）

| IOCTL | function | 缓冲区需求 | 底层 USB 动作 | 处理函数 |
|---|---|---|---|---|
| `0xC321A000` | 0x2800 | In ≥ 2 | vendor OUT，`bRequest=0x00`，`wValue = *(u16)in`，无数据 | `FUN_140006b50` |
| `0xC321A004` | 0x2801 | In ≥ 2 | vendor OUT，`0x01`，`wValue = *(u16)in` | `FUN_14000801c` |
| `0xC321A00C` | 0x2803 | In ≥ 2 | vendor OUT，`0x03`，`wValue = *(u16)in` | `FUN_1400083e4` |
| `0xC321A014` | 0x2805 | In ≥ 2 | vendor OUT，`0x05`，`wValue = *(u16)in` | `FUN_1400080b4` |
| `0xC321A018` | 0x2806 | In ≥ 1 | vendor OUT，`0x06`，`wValue = *(u8)in`（零扩展） | `FUN_14000834c` |
| `0xC321A01C` | 0x2807 | In ≥ 2 | vendor OUT，`0x07`，`wValue = *(u16)in` | `FUN_14000847c` |
| `0xC321A024` | 0x2809 | 无 | vendor OUT，`0x09`，无数据 | `FUN_14000863c` |
| `0xC321A028` | 0x280A | 无 | vendor OUT，`0x0A`，无数据 | `FUN_1400085ac` |
| `0xC321A02C` | 0x280B | In ≥ 2 | vendor OUT，`0x0B`，`wValue = *(u16)in` | `FUN_140008200` |
| `0xC321A034` | 0x280D | In ≥ 2 | vendor OUT，`0x0D`，`wValue = *(u16)in` | `FUN_140008514` |
| `0xC321A044` | 0x2811 | 无 | vendor OUT，`0x11`，无数据 | `FUN_140007470` |
| `0xC321A048` | 0x2812 | In ≥ 2 | vendor OUT，`0x12`，`wValue = *(u16)in` | `FUN_1400073d8` |
| `0xC321A04C` | 0x2813 | In ≥ 16 | vendor OUT，`0x13`，**16 字节数据**（输入缓冲直接作为 payload） | `FUN_140008298` |
| `0xC321A054` | 0x2815 | In ≥ 2 | vendor OUT，`0x15`，`wValue = *(u16)in` | `FUN_140006ab8` |
| `0xC321A064` | 0x2819 | In ≥ 6 | vendor OUT，`0x19`，**6 字节数据** | `FUN_14000814c` |
| `0xC321A078` | 0x281E | In ≥ 4 | vendor OUT，`0x1E`，**4 字节数据**（不返回传输长度） | `FUN_140007f68` |
| `0xC321A084` | 0x2821 | 任意（=写入字节数） | **输入缓冲 → 写 OUT 管道**，异步完成 | `FUN_1400011a4` |

> 说明：`0xC321A000` 的 `bRequest = 0x00` 是通过 `byte[rbp-0x1f] = 0` 实现的（`FUN_140006b50`），并非遗漏。

---

## 4. USB 控制请求（线上字节，已确证）

所有请求都由 `WdfUsbTargetDeviceSendControlTransferSynchronously(UsbDevice, NULL, &sendOptions, &setupPacket, &memDesc, &bytes)` 发出。

### 4.1 IN 组（读）

`bmRequestType = 0xC2`（bit7=1 device→host，bits6-5=10 vendor，bits4-0=00010）、`wIndex = 0`、`wValue = 0`

| bRequest | 数据长度 | 对应 IOCTL |
|---|---|---|
| `0x02` | 2 | `0xC3216008` |
| `0x04` | 2 | `0xC3216010` |
| `0x08` | 1 | `0xC3216020` |
| `0x0C` | 2 | `0xC3216030` |
| `0x0E` | 6 | `0xC3216038` |
| `0x0F` | 256 | `0xC321603C` |
| `0x10` | 19 | `0xC3216040` |
| `0x14` | 16 | `0xC3216050` |
| `0x16` | 2 | `0xC3216058` |
| `0x1D` | 4 | `0xC3216074` |

### 4.2 OUT 组（写）

`bmRequestType = 0x41`（bit7=0 host→device，bits6-5=10 vendor，bits4-0=00001）、`wIndex = 0`；除注明外 `wLength = 0`

| bRequest | wValue | 数据长度 | 对应 IOCTL |
|---|---|---|---|
| `0x00` | `*(u16)in` | 0 | `0xC321A000` |
| `0x01` | `*(u16)in` | 0 | `0xC321A004` |
| `0x03` | `*(u16)in` | 0 | `0xC321A00C` |
| `0x05` | `*(u16)in` | 0 | `0xC321A014` |
| `0x06` | `*(u8)in` | 0 | `0xC321A018` |
| `0x07` | `*(u16)in` | 0 | `0xC321A01C` |
| `0x09` | 0 | 0 | `0xC321A024` |
| `0x0A` | 0 | 0 | `0xC321A028` |
| `0x0B` | `*(u16)in` | 0 | `0xC321A02C` |
| `0x0D` | `*(u16)in` | 0 | `0xC321A034` |
| `0x11` | 0 | 0 | `0xC321A044` |
| `0x12` | `*(u16)in` | 0 | `0xC321A048` |
| `0x13` | 0 | 16 | `0xC321A04C` |
| `0x15` | `*(u16)in` | 0 | `0xC321A054` |
| `0x19` | 0 | 6 | `0xC321A064` |
| `0x1E` | 0 | 4 | `0xC321A078` |

> ⚠ 说明：驱动把 `WDF_USB_CONTROL_SETUP_PACKET.Length` 字段写成 0，实际数据长度来自 `WDF_MEMORY_DESCRIPTOR.Length`。Windows USB 栈会把它映射成 URB 的 `TransferBufferLength`（即线上的 `wLength`），所以线上仍会看到 1/2/4/6/16/19/256 的长度。真机抓包可验证。

### 4.3 数据通路（不走控制请求）

| 方向 | 触发方式 | 驱动动作 |
|---|---|---|
| 设备 → 主机 | `ReadFile()` 或 `DeviceIoControl(0xC3216080, outBuf, N)` | `WdfRequestRetrieveOutputMemory` → `WdfUsbTargetPipeFormatRequestForRead(ctx->pipeIN, Request, mem, 0)` → `WdfRequestSetCompletionRoutine` → `WdfRequestSend`（异步；完成例程用管道信息填 `Information` 完成请求） |
| 主机 → 设备 | `WriteFile()` 或 `DeviceIoControl(0xC321A084, inBuf, N)` | `WdfRequestRetrieveInputMemory` → `WdfUsbTargetPipeFormatRequestForWrite(ctx->pipeOUT, Request, mem, 0)` → 同上 |

---

## 5. 上报数据结构 = 没有结构

这是本次逆向最需要说清楚的一点：

1. **驱动不解析红外码**。全二进制里没有任何协议/解码/环形缓冲/定时器代码，也没有 IR 相关的字符串、结构体或常量。它把设备当成"黑盒 + 两块内存"：控制请求传参、管道传数据。
2. **所谓"上报"只有两种形态**：
   * 定长读取：上表 IN 组的 1/2/4/6/16/19/256 字节，内容由固件定义，驱动只是零填充缓冲区后原样返回（`FUN_140006cb0` 等函数开头的 `memset`）。
   * 变长直通：IN 管道的原始字节流，长度由调用方决定/由实际传输决定（`IoStatus.Information` 给出实际字节数）。
3. 因此**数据结构的字段含义必须从设备固件或索尼用户态程序（本包不含）反推**。可以从长度与配对关系做的工作假设：

| 假设 | 依据 |
|---|---|
| `0x0F`(256B) = 遥控码表 / 学习缓冲 / 能力表 之类的大块数据 | 唯一一次大块读取 |
| `0x13`/`0x14` 或 `0x1D`/`0x1E` = 同一结构的"写/读"配对（16 字节 / 4 字节） | 双向同长度 |
| `0x02/0x04/0x08/0x0C/0x16` = 状态、版本、能力等短查询 | 1~2 字节返回 |
| `0x10`(19B) = 版本串/序列号一类（19 字节很像字符串+结尾） | 长度特征 |
| 带 `wValue` 的 OUT 命令 = "设置某个 16 位参数/模式" | 参数只有一个 16 位值 |
| `0x19`(6B 写) / `0x0E`(6B 读) = 一个 6 字节记录（如一次完整红外帧/载波参数） | 长度接近典型 IR 帧 |

这些**是假设，不是结论**：验证方式是真机抓 USB 流量 + 用索尼原厂 VAIO 应用（"IR Remote Control"/"VAIO Remote"）操作时对比。

---

## 6. 与 WinUSB 路线的关系（对"能不能在现代系统上用"很关键）

INF 里有两套安装段：

```ini
[Manufacturer]
%ManufacturerName%=Standard,NTamd64.6.2,NTamd64.6.3

[Standard.NTamd64.6.2]           ; Windows 8
%SIRD.DeviceDesc%=SIRD_Device, USB\VID_054C&PID_06D9      ; → 装 SIRD.sys（本文分析的 KMDF 驱动）

[Standard.NTamd64.6.3]           ; Windows 8.1 及以上（含 Win10/11，取最高匹配段）
%SIRD.DeviceDesc%=USB_Install, USB\VID_054C&PID_06D9
%SIRD.DeviceDesc%=USB_Install, USB\VID_054C&PID_0883
[USB_Install.HW]                 ; → 用系统自带 winusb.inf
HKR,,DeviceInterfaceGUIDs,0x10000,"{AC2C0F91-97D5-452D-8F89-E055C8C498A4}"
```

推论（重要）：

* 在 **Win8.1 / Win10 / Win11** 上安装本包时，走 `6.3` 段 → 绑定 **in-box WinUSB**，`SIRD.sys` 不会被加载，`{D9527091-...}` 接口也不会出现；用户态应用改成用 `{AC2C0F91-...}` + WinUSB API 直接操作设备。
* 也就是说 **§3/§4 的协议在两条路径上是同一套**：Sony 只是把驱动里那 26 个控制请求和 2 条管道搬到了用户态。要在现代系统上复现，只需：
  1. 让设备绑定 WinUSB（装这份 INF，或用 Zadig 手动绑定），
  2. 打开接口 `{AC2C0F91-97D5-452D-8F89-E055C8C498A4}`，
  3. `WinUsb_ControlTransfer` 发 §4 的请求、`WinUsb_ReadPipe/WritePipe` 收发 §4.3 的数据。
* 缺失的唯一信息是**端点描述符**（地址/类型/包长）——驱动全部从描述符动态读取，没有任何硬编码；必须在真机上枚举（`UsbTreeView`、`lsusb -v`，或 `WinUsb_QueryPipe`）。

---

## 7. 未确证 / 待真机确认清单

1. ~~`PipeType == 3` 是 Bulk 还是 Interrupt~~ → **已确认：Bulk**（§9）。
2. ~~端点地址、`wMaxPacketSize`~~ → **已确认：EP 0x01 OUT / EP 0x82 IN、Bulk、64 字节、Full Speed、1 个接口（类 0xFF）**（§9）。`bInterval` 对 Bulk 无意义。
3. ~~`wLength` 线上实际值~~ → **已确认**：真机上 `WinUsb_ControlTransfer` 按 `SetupPacket.Length` 发送，实测 `GET_DESCRIPTOR(18)` 返回 18 字节、厂商请求 `0x0F` 返回 66 字节（首字节即总长），即"长度由请求方给出、设备可短包回应"。§4 表中标注的长度与实际一致。
4. 各 bRequest 的业务语义与返回结构字段布局 → **部分已解**（§9：`0x01↔0x02`、`0x13↔0x14`、`0x19↔0x0E`、`0x1E↔0x1D` 四组 set/get 已实测确认；`0x0F` 自描述块含固件版本 "3.0"；`0x10` 是 19 字节状态块）。剩余字段含义、以及"哪个请求/管道承载红外码"仍需按遥控器实测。
5. `PID_0883` 与 `PID_06D9` 的差异 —— **0883 实测是第三方"Silicom Labs IR Adapter"**，固件版本 "3.0"；06D9 未实测。两者共用 §3/§4 的请求编号，但 0883 固件对 `0x03`、`0x06`（部分状态）、`0x12`（带数据时）会 STALL，说明并非全部实现。
6. `0xC321A078`(4B 写) 不返回传输长度（`BytesTransferred = NULL`），`0xC321A04C`/`0xC321A064` 也类似——写命令不要依赖 `lpBytesReturned`。

---

## 8. 产出文件 / 复现方法

| 文件 | 说明 |
|---|---|
| `RE/sird_x64_decompiled.c` | Ghidra 反编译的 x64 全函数 C 代码（54/58 个函数成功） |
| `RE/x64_disasm.txt` | capstone 线性反汇编（带 RIP 相对目标、导入名、GUID 标注） |
| `RE/01_pe_recon.py` | PE 头/导入/GUID/宽字符串扫描 |
| `RE/02_disasm.py` | 反汇编 + 交叉标注 |
| `RE/03_x86_compare.py` | x86 与 x64 的 IOCTL 常量集对比（结果：完全一致） |
| `RE/ghidra_scripts/DecompileAll.java` | Ghidra headless 反编译脚本 |
| `RE/ida_dump.py` | IDA headless 反编译脚本（本机因 IDA 写注册表被沙箱拒绝而未使用） |
| `RE/tools/sird_winusb.py` | **零依赖用户态工具**（ctypes 直调 SetupAPI/WinUSB）：`list / enumerate / scan / in / out / ctrl / pipe-read / pipe-write / watch / ioctl` |
| `RE/tools/probe_map.py` | OUT 参数 → IN 状态映射、写读配对验证、状态复原 |
| `RE/tools/probe_pipe.py` | 管道通路自检 / 回环测试 |
| `RE/tools/probe_busy.py` | 检查管道是否被写满、小数据写入后是否有应答 |
| `RE/tools/probe_flush.py` | 验证 `0x10[12..15]` 语义 + 找清空命令（→ `0x12`） |
| `RE/tools/probe_go.py` | 找"发射触发"命令（→ `0x00`） |
| `RE/tools/probe_emit.py` | 红外发射判定（配合手机摄像头） |
| `RE/tools/probe_sweep.py` | 模式扫描 + 实时监视（排查"按遥控器无反应"） |
| `RE/tools/probe_tx.py` | 安全版发射/触发试探（小数据、超时即停） |
| `RE/tools/probe_clear.py` | 试探清除 `0x10[17]` 粘滞标志 |
| `RE/tools/session_evidence.txt` | §9 真机实测的原始输出留档（描述符 / IN 扫描 / 配对验证 / 状态变化） |
| `RE/work/SIRD_x64.sys` / `SIRD_x86.sys` | 分析用副本（原文件未改动） |

复现命令：

```powershell
# 反汇编
python RE\02_disasm.py RE\work\SIRD_x64.sys RE\x64_disasm.txt

# Ghidra 反编译（需要 JDK21；把 user.home/APPDATA 重定向到工作区以避开沙箱）
$gh='D:\harness\SonyIR\RE\ghidra_home'
$env:JAVA_HOME='C:\Program Files\Java\jdk-21.0.10'
$env:APPDATA="$gh\AppData"; $env:LOCALAPPDATA="$gh\AppData"
$env:TMP="$gh\tmp"; $env:TEMP="$gh\tmp"; $env:_JAVA_OPTIONS="-Duser.home=$gh"
& 'D:\Tools\ghidra_11.4.2_PUBLIC\support\analyzeHeadless.bat' `
  'D:\harness\SonyIR\RE\ghidra_proj' SonyIR_x64 `
  -import 'D:\harness\SonyIR\RE\work\SIRD_x64.sys' `
  -scriptPath 'D:\harness\SonyIR\RE\ghidra_scripts' `
  -postScript DecompileAll.java 'D:\harness\SonyIR\RE\sird_x64_decompiled.c' -deleteProject
```

---

## 9. 真机实测（本机 PID_0883 "IR Adapter"）

### 9.1 设备身份与描述符

* 接口路径：`\\?\usb#vid_054c&pid_0883#0082ba65#{ac2c0f91-97d5-452d-8f89-e055c8c498a4}`
  → 它**已经**绑在 INF 6.3 段的 WinUSB 接口 GUID 上（KMDF 的 `{D9527091-...}` 接口为 0 个设备），即 `SIRD.sys` 根本没参与。
* 设备描述符：`12 01 00 02 00 00 00 40 | 4C 05 | 83 08 | 00 01 | 01 02 03 | 01`
  → USB2.0、`bMaxPacketSize0=64`、VID 0x054C、PID 0x0883、bcdDevice 0x0100、iMan=1/iProd=2/iSer=3、1 个配置
* 配置描述符（32 字节）：
  `09 02 20 00 01 01 00 80 32`（1 接口、总线供电、100 mA）
  `09 04 00 00 02 FF 00 00 02`（接口类 **0xFF 厂商自定义**、2 端点）
  `07 05 01 02 40 00 00`（**EP 0x01 OUT / Bulk / 64B**）
  `07 05 82 02 40 00 00`（**EP 0x82 IN / Bulk / 64B**）
* 字符串描述符：iManufacturer = **"Silicom Labs"**、iProduct = **"IR Adapter"**、iSerial = **"0082BA65"**
  → **这不是索尼自家硬件**：第三方红外适配器借用了 Sony 的 VID/PID，以便 VAIO 的驱动/软件认它。这正好解释了 INF 为什么在 6.3 段额外列出 PID_0883。
* 由此确认 §2.4 的推断：驱动按 `PipeType == 3` 挑的管道就是 **Bulk**（`WDF_USB_PIPE_TYPE: Invalid=0, Control=1, Isochronous=2, Bulk=3, Interrupt=4`）。

### 9.2 写 WinUSB 客户端时踩到的两个坑（都会伪装成"设备不响应"）

1. `WinUsb_Initialize` 要求文件句柄以 **`FILE_FLAG_OVERLAPPED`** 打开，否则 WinError 6；而一旦是 overlapped 句柄，所有 `WinUsb_ControlTransfer` / `ReadPipe` / `WritePipe` 都**必须**传有效的 `OVERLAPPED` + 事件，传 NULL 会直接 access violation（进程 0xC0000005 崩掉）。
2. IN 传输的缓冲区必须按**传输长度（wLength）**分配，不能按"已有数据长度"分配。按后者分配会只给 1 字节缓冲却声明传 18/64/256 字节 → 越界写 + 返回字节数错乱。症状很有迷惑性：`GET_DESCRIPTOR(device,18)` 只回 1 字节 `0x12`。

---

### 9.3 控制请求实测结果（bmRequestType 0xC2 = IN / 0x41 = OUT，与 §4 完全一致）

| IN 请求 | 初始响应 | 实测结论 |
|---|---|---|
| `0x02` (2B) | `20 00` | 16 位参数，初值 0x20（**`0x01` 的读回口**） |
| `0x04` (2B) | `00 08` | 常量 0x0800，试验中未变 |
| `0x08` (1B) | `00` | 随 `0x13` 写入内容变化：写 16×0xAA → `03`；写 16×0x00 → `00` |
| `0x0C` (2B) | `00 00` | 未观察到变化 |
| `0x0E` (6B) | `00…` | **`0x19` 的读回口** |
| `0x0F` (256B) | **66 字节自描述块**，首字节 `0x42`=66，末尾 UTF-16 `"3.0"` | 固件/能力块；含多个位图字段（`7F 00 00 00`、`3F 01 00 00`、`FE FF 07 10`…） |
| `0x10` (19B) | 见下方状态块 | 状态/标志块（被 `0x09`/`0x0A`/`0x13`/`0x06` 改写） |
| `0x14` (16B) | `00…` | **`0x13` 的读回口** |
| `0x16` (2B) | `00 00` | 未观察到变化 |
| `0x1D` (4B) | `00 C2 01 00` = **0x0001C200 = 115200** | **`0x1E` 的读回口**（疑似波特率/时基类参数） |
| 管道 `0x82` | 静置读超时（WinError 121，无数据） | 符合"无红外事件不推送"；**是否承载红外码仍需按遥控器验证** |

**已实测确认的四组 set/get 配对**（写什么、读回什么，逐字节一致）：

| 写 | 形式 | 读回 | 长度 |
|---|---|---|---|
| `OUT 0x01` | wValue = 16 位 | `IN 0x02` | 2 |
| `OUT 0x13` | 16 字节负载 | `IN 0x14` | 16 |
| `OUT 0x19` | 6 字节负载 | `IN 0x0E` | 6 |
| `OUT 0x1E` | 4 字节负载 | `IN 0x1D` | 4 |

**其他已观察到的行为**：

* `OUT 0x0A`（无参）→ 状态块 `0x10[4] |= 0x08`；`OUT 0x09` → 清掉该位。即 `0x0A`/`0x09` = 使能/禁止某功能位。
* `OUT 0x13` 写入**非零**数据 → `0x10[4]` 出现 0x01/0x04 位；写全零 → 这些位消失（与 `IN 0x08` 同步变化）。
* `OUT 0x06`（8 位参数）成功一次后把 `0x10[17]` 置 1，此后重复发送一律 **STALL**，且其它命令清不掉这一位 → 推断为"配置已变更/已提交"的粘滞标志，掉电重新插拔应复位。
* **STALL（WinError 31）**：`0x03`（任何 wValue）、`0x06`（重复发送）、`0x12`（带 4 字节数据时）。`0x12` 的 STALL 说明它只接受 wLength=0 的形式。
* `0x10` 状态块当前值 `00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 01 00`：`byte[4]` 是功能位（0x08 = 已由 `0x0A` 使能），`byte[17]` 是上面那个粘滞标志。

### 9.4 复现命令

```powershell
python RE\tools\sird_winusb.py list                # 描述符与端点
python RE\tools\sird_winusb.py scan --dump         # 跑一遍全部 IN 请求
python RE\tools\sird_winusb.py out 0x01 0x20       # 写 0x01，再 in 0x02 看是否读回
python RE\tools\sird_winusb.py in 0x02 2
python RE\tools\sird_winusb.py watch --seconds 60  # ★ 按遥控器，看管道/状态有没有变化
python RE\tools\probe_map.py                       # 参数->状态映射 + 配对验证
python RE\tools\sird_winusb.py ctrl 0x80 0x06 0x0100 0 18   # 标准 GET_DESCRIPTOR（验证传输层）
```

工具只依赖 Python 标准库 `ctypes`；实测设备已绑 WinUSB，**不需要**安装 `SIRD.sys`。

---

### 9.5 管道那一半的真相：OUT 管道 = 红外发射缓冲（实测）

这是本轮最有价值的发现。对 OUT 管道(0x01) 反复写数据并观察状态块，得到：

| 观察 | 结论 |
|---|---|
| 写 2 字节 → `0x10[12..15]` 读回 2；再写 6 字节 → 读回 **8** | `0x10[12..15]` = **OUT 管道里待处理（未被消费）的字节数**（u32 LE），会累加 |
| 灌 64 字节垃圾后再写任何长度都超时 | 该缓冲堆满后 bulk OUT 端点不再接受数据（我把设备写"堵"了） |
| `OUT 0x12`（**必须 wLength=0**）→ 计数 8 → **0**，随后管道写立刻恢复 | `0x12` = **清空发射缓冲**；也是堵死后的恢复手段（不必拔插）。带数据发 `0x12` 会 STALL |
| 8 字节待处理时逐条试命令：只有 `OUT 0x00` 让计数 8 → 0 | **`OUT 0x00`(w16) = 发射触发**（唯一会消费缓冲的命令；wValue 疑似重复次数/参数） |
| `0x10[4]` 位图：`0x0A` 置 0x08、`0x09` 清 0x08、`0x05` 置 0x20 | 三个功能开关位 |
| IN 管道(0x82)：16 次写入试验 + 8 秒 `watch` + 按遥控器，始终无数据 | 未观察到接收通路 |

**由此得到的完整发射流程**：

```
1) 往 OUT 管道(0x01) 写红外数据（字节格式待解，见下）
2) OUT 0x00  [wValue=?]        # 触发发射
3) IN 0x10 读 byte[12..15]      # 0 = 数据已被消费
   出错/中断时：OUT 0x12 (wLength=0) 清空缓冲
```

也就是说：**PID_0883 "IR Adapter" 至少是一个红外发射器（blaster）**——这解释了为什么"按遥控器毫无反应"：它根本没有（或未启用）接收通路，数据方向是 PC → 设备 → 红外 LED。

尚未确定的是**发射数据的字节格式**（时序编码？载波参数 + 码？），以及 `0x00` 的 wValue 含义。这两点可以用手机摄像头 + `probe_emit.py` 逐步收敛：摄像头能看到红外闪烁就说明格式被接受了。注意红外光肉眼不可见，**必须用手机摄像头**看。

---

## 10. 原厂应用侧逆向（VGP-URM10.7z → VAIO Remote Control 应用）

用户后来找到了原厂软件包 `VGP-URM10.7z`，内容与结论如下。

### 10.1 包里是什么

| 文件 | 说明 |
|---|---|
| `BD9B8345.VAIORemotecontrol_1.0.1.6190_x64__*.Appx` / `_1.1.2.12170_*.Appx` | **VAIO Remote Control** 应用（Store 包，2013，Win8.1 起） |
| `Microsoft.VCLibs.110/120.00_*.Appx` | 应用私有 VC++ 运行库（含 `vccorlib120_app.dll` 等） |
| `SODOTH-P0311568-1102.EXE` | 另一个索尼安装包 |
| `SOURCES.txt` | 用户留的来源说明：driver 来自 rebyte.me、Appx 从 Microsoft Store（store.rg-adguard.net）抓取 |

### 10.2 设备真相（结合硬件实测）

* 应用清单声明 `m2:DeviceCapability Name="usb"` + `vidpid:054c 06d9` / `054c 0883`。
* 应用同时支持两条路径：
  * `{d9527091-ac8b-4d57-8ec7-ca0790dbcbbd}`（= SIRD.sys 的 KMDF 设备接口）
  * `{DEE824EF-729B-4A0E-9C14-B7117D33A817}`（WinRT `Windows.Devices.Usb` 接口）**AND** `System.DeviceInterface.WinUsb.DeviceInterfaceClasses:~="{AC2C0F91-97D5-452D-8F89-E055C8C498A4}"`
    → 与 §6 的推断完全一致：Win8.1+ 走 WinUSB + WinRT USB API。
* 应用里静态链接了 **UEI QuickSet 码库 SDK**（导出 49 个 `QS_*` 函数），并有 `LearnDeviceButtonCodeAsync`（**学习红外码**）、`SendKeyCode`/`SendKeyCodeContinuously`、宏（Macro）等能力。
  → 设备是 **UEI（Universal Electronics）方案的收发模块**，Sony 只是贴牌成 VGP-URM10；"三颗灯珠"里应有接收头，学习功能靠它。
* 码库配置 `cmd.conf`：`dbroot:=en`（→ `en_dac1/2/3` 加密库）、`wsurl:=https://securetest.ueiqickset.com/QuickSetLite.svc`（在线码库）、`devmap` 设备类型映射。
* 应用内 `CommonXML\*.BIN` 共 207 个（`DeviceTypeNumList_*.BIN`、`layout_table_*.upd5.BIN`、`MakerFilterList_*.BIN`）——同款加密头 `30 6a 90 99 e3 a6 24 b6 …`，是 UI 用的类型/品牌/型号表。

### 10.3 关键成果：把码库在应用外面跑起来

`Sony.VAIO.VAIORemotecontrol.IRLayer.dll` 的 `QS_*` 是**导出函数**，因此可以直接在普通进程里 `ctypes` 调用（需要把 VCLibs 的 `*_app.dll` 和应用目录里的 `en_dac*`、`cmd.conf` 放在一起）。

实测结果（`RE/tools/qs_host.py`）：

```
QS_start("cmd.conf") -> 0
version = v1.9.7.1_RC1      localDB = Sony_Android_database_v3.2_sonytab
设备类型 10 个：TV / Cable,IPTV / Video Accessory / Satellite,DSS / VCR / DVD /
               Receiver,Misc Audio / Amplifier / CD / Home Control
TV 品牌 1762 个，Cable/IPTV 608 个 ……（完整离线码库）
```

应用自己的调用范式（反编译 `FUN_180065120` 得到，已照抄成 `RE/tools/qs_dump.py`）：

```c
QS_start("cmd.conf");
QS_retrieve_device_types();  QS_get_device_type_name(i);
QS_retrieve_brands(typename, brandFilter);   QS_get_brand_name(j);
QS_retrieve_codesets_by_brand(j);            QS_get_codeset_name(k);
QS_get_codeset_binary(codesetName, &buf, &size);   // ← 真实红外码
QS_stop();
```

**已成功提取真实码**：TV → Sony → 6 个 codeset（`T4090`…`T4095`），其中 `T4090` 的 codeset binary = **116 字节**（存为 `VGP-URM10/codeset_sony_tv_0.bin`）：

```
00 02 A2 43 2E 03 97 6A 30 3A 0C 37 63 1A 0D B4 A8 75 93 DD 34 C2 0A 50 ...
```

### 10.4 下发帧格式（反编译 `FUN_18010c690`）

```
[0]   (payload+3) >> 8     长度高（大端）
[1]   (payload+3) & 0xFF   长度低
[2]   0x22                 操作码
[3]   flags >> 8           } 由 6 字节"会话值"（1 个字母 + 4 位数字）派生：
[4]   flags & 0xFF         }   A→0x8000, C→0x1000, D→0x9000, H→0xA000, M/Q→0x7000,
                               N→0x2000, S→0x3000, V→0x4000, Y→0x6000
[5..] payload              码数据（就是上面的 codeset binary）
```
长度字段 = 操作码 + flags + payload（即 payload+3）。学习功能走同一个帧构造器，所以 `0x22` 大概率是"把这段数据交给 IR 引擎"的通用操作码。

结合 §9 的实测（`0x00` = 执行/消费管道里待处理数据），完整下发链路应为：
**写帧到 OUT 管道 → `OUT 0x00` 执行 → 读 `IN 0x10[12..15]` 确认**。

### 10.5 还没打通的最后一环

* **会话值/`flags` 的来源**：`FUN_1800f6010` 取全局 6 字节缓冲（形如"字母+4位数字"），`flags` 由它的首字母与后 4 位数字决定。这个值由谁、何时写入尚未定位（可能是与设备的会话/时间种子）。
* **按键命令**：码库下发之后，"按某键"应是另一条命令（可能是 A 组的 w16 命令之一，wValue = 按键码）。
* **实测现象**：用 `RE/tools/probe_codeset.py` 把 6 种 flags 的帧写进管道后，`0x10[12..15]` 待处理数**保持 0**（此前写 1 字节都会累加）——说明设备这次把数据直接吃掉了（可能进了"流式"状态），但没有任何状态变化、LED 也不亮。建议**拔插设备复位后重试**，并用手机摄像头同时观察三颗灯珠。

---

## 附：判读 WDF 调用的依据（关键槽位 → API）

驱动是 KMDF 静态链接，DDI 调用全部通过 `.data` 里的函数指针槽 + `WdfDriverGlobals`，因此报告里的 API 名称是**按调用约定与参数结构逐一比对得出的**（非符号）：

| 槽位 | 判定为 | 依据 |
|---|---|---|
| `0x1400036d8` | `WdfIoQueueGetDevice` | 入参 = Queue（EVT_IO_DEVICE_CONTROL 第 1 参数），返回句柄再喂给下一个调用 |
| `0x140003840` | `WdfObjectGetTypedContext` | 第 3 参数 = `PTR_DAT_140003118`（`WdfDeviceCreate` 时注册的 ContextTypeInfo） |
| `0x140003a58` / `0x140003a60` | `WdfRequestRetrieveInputBuffer` / `...OutputBuffer` | Axxx 组用前者且检查 `InputBufferLength`，6xxx 组用后者且检查 `OutputBufferLength` |
| `0x140003a48` / `0x140003a50` | `WdfRequestRetrieveInputMemory` / `...OutputMemory` | 与管道读写的方向严格对应 |
| `0x140003c58` | `WdfUsbTargetDeviceSendControlTransferSynchronously` | 5 参数 = (UsbDevice, Request=NULL, &SendOptions, &SetupPacket, &MemDesc, &BytesTransferred)；`SendOptions{Size=0x10, Flags=1(TIMEOUT), Timeout=-5s}`；`MemDesc{Type=1(Buffer), Buffer, Length}` |
| `0x140003cc8` / `0x140003cd8` | `WdfUsbTargetPipeFormatRequestForWrite` / `...Read` | 接到 `ctx->OUT pipe` / `ctx->IN pipe` |
| `0x140003a10` / `0x1400039d8` | `WdfRequestSetCompletionRoutine` / `WdfRequestSend` | Send 返回 BOOLEAN，失败时走 `0x1400039e0` 分支 |
| `0x140003a38` | `WdfRequestCompleteWithInformation` | (Request, Status, Information)，Information 取自处理函数回填的局部 dword |
| `0x140003590` / `0x140003448` | `WdfDriverCreate` / `WdfDeviceCreate` | 结构体 Size 0x20/0x38 与字段布局完全吻合 |
| `0x140003458` / `0x140003468` | `WdfDeviceCreateDeviceInterface` / 同一接口的查询类 API | 第 3 参数 = `.rdata+0xC0` 的 GUID `{D9527091-...}`，第 4 参数 = NULL（`FUN_140006008` 中两处调用，后者与 `IoSetDeviceInterfacePropertyData` 配合） |
| `0x140003d58` / `0x140003cb8` / `0x140003ca0` / `0x140003ca8` | `WdfUsbInterfaceGetConfiguredPipe` / `WdfUsbTargetPipeSetNoMaximumPacketSizeCheck` / `IsInEndpoint` / `IsOutEndpoint` | 0x14 字节 `WDF_USB_PIPE_INFORMATION`、`+0xC` 与 3 比较、两个返回 BOOLEAN 的 1 参数调用 |
| `0x140003f18` / `0x140003c40` | `WdfUsbTargetDeviceCreateWithParameters` / `WdfUsbTargetDeviceSelectConfig` | config `{Size=8, USBDClientContractVersion=0x0602}`；select `{Size=0x20, Type=3}`，第 5 参数 = `&ctx->UsbDevice` |
| `0x140003ad0` | `WdfRequestStopAcknowledge` | `EvtIoStop` 中 `(Request, FALSE)` |

---

## 11. 最终成果：设备协议完全还原（USBPcap 抓包 + 复现验证）

### 11.1 抓包环境（终于搞定）

* **USBPcap 其实一直都装着、也挂上了**——只是 `dumpcap -D` 在非管理员下看不到 `\\.\USBPcapN`（WinError 5 = 存在但拒绝访问），我前期据此误判了好几轮。
* 真正好用的是 **USBPcapCMD.exe**（`-d \\.\USBPcap2 -o out.pcap -b 4096 -A --inject-descriptors`），
  它在**普通用户会话**下就能抓；`dumpcap -i USBPcap1/2` 则需要管理员。
* 本机设备在该抓包接口下的设备地址会变（2 → 6），解析时要按 `usb.idVendor==0x054c` 定位。
* 解析：`RE/tools/parse_usbpcap.py`，或 `tshark -Y "usb.device_address==N" -T fields -e usb.capdata ...`

### 11.2 应用真实下发的完整序列（逐字节）

```
1) 初始化（一次）
   0x41 bReq=0x00 wValue=0x0001                  执行/启动
   0x41 bReq=0x1E wLength=4  data=00 4B 00 00    写 4 字节寄存器 = 19200
   0x41 bReq=0x19 wLength=6  data=1A 00 00 1A 11 13

2) 注册握手（一次）
   OUT 管道 00                                    每个命令前的固定 1 字节
   OUT 管道 40 41 42 43 00 01 11                  7 字节握手帧
   IN  管道 -> 04 00 01 0F FD                     回应：长度 4 + 00 01 0F FD
                                                  **设备 ID = 0F FD**

3) 每次按键
   OUT 管道 00
   OUT 管道 40 41 42 43 00 07 01 0F FD XX 80 00 00
              └ magic ┘ └长度┘ └类型┘ └ID ┘ └按键码┘└ 0x80=按下 / 0x00=松开
   IN  管道 -> 01 00                              应答
```

### 11.3 命令帧通用格式（从 IRLayer.dll 的构造器逐个读出）

```
[40 41 42 43] [len_hi] [len_lo] [type] [ID lo] [ID hi] [ (flag) ] [payload...]
   len = payload 长度 + 4（type 0x22）/ +5（type 0x10，多一个 flag 字节）
```

| type | 结构 | 含义 |
|---|---|---|
| `0x11` | `magic 00 01 11`（7 字节） | 注册握手 |
| `0x01` | `magic 00 07 01 ID2 按键码 80/00 00 00` | **按键按下/松开**（13 字节，已抓包验证） |
| `0x22` | `magic len 22 ID2 payload…` | 下发数据（码库）——QS 层那个 `0x22` 帧走的就是这里 |
| `0x10` | `magic len 10 ID2 {0x90|0x10} payload…` | 另一种下发 |
| `0x12` / `0x02` | `magic 00 03 12/02 [2 字节]` | 带 16 位参数 |

**关键时序**：每个命令前必须写 1 字节 `00`，随后 **≥50 ms** 再写命令帧（0 ms → 1/3 成功率；50/120 ms → 3/3）。
另外设备有**命令洪水保护**：连续大量无效命令后会静默数十秒。

> ★ **§26 已把这套时序量准了**：真正的要求是"解锁与帧之间 ≥约 3 ms"（不是 50 ms），
> 而所谓"洪水保护"其实是**装载窗口被打坏后需要约 400 ms 完全静默**——见 §26。

### 11.4 已实现并可复现的工具

`RE/tools/sird_blast.py`：独立发码工具（不需要官方应用）

```
python sird_blast.py --list                 # 已知按键码
python sird_blast.py --code 0x01 --hold 3   # 发某个码（长按 = 连发）
python sird_blast.py --sweep                # 依次试所有抓到的按键码（每秒一个，便于对照电视反应）
python sird_blast.py --download <bin> --dtype 0x22 [--dflag 0x90]   # 下发码库
```

实测：初始化 → 握手拿到 `ID=0F FD` → 按键帧与抓包**逐字节一致**并被设备应答 `01 00` ✓

### 11.5 仍未闭环的一点

* `type=0x22` 直接下发从应用码库抠出的 116 字节 codeset（Sony TV `T4090`）会被设备 **NACK（`01 07`）**，
  说明该载荷还需要包装（或需要前置命令，例如 type `0x10`/`0x12`/`0x02` 的组合）。
* 因此"任意品牌任意码"这一档还差最后一步；但**设备内已有码库**时（应用注册时下过），
  用 `--sweep` 逐个试按键码就能让它发射。

### 11.6 抓包留档

| 文件 | 内容 |
|---|---|
| `RE/capture/app_traffic2.pcap` | 应用注册失败的序列（3 控制 + 2 管道写 + 管道读取消） |
| `RE/capture/app_traffic3.pcap` | **应用正常工作时的完整序列**（握手 + 70 多次按键命令，含全部按键码） |
| `RE/capture/selftest2.pcap` | 我们自己制造的已知流量（验证抓包→解析链路） |

---

## 12. 学习（接收）功能与码表写入（本轮新成果）

### 12.1 抓包环境要点（血泪教训）

* USBPcap 装好后 `dumpcap -D` 在**非管理员下看不到** `\\.\USBPcapN`（WinError 5 = 存在但拒绝访问），
  但 **USBPcapCMD.exe 在普通会话下就能抓**：
  `USBPcapCMD.exe -d \\.\USBPcap2 -o out.pcap -b 4096 -A --inject-descriptors`
* USBPcapCMD 只在**有 USB 流量**时才写盘（缓冲 4 KB），所以"文件只有 3 KB"= 那段时间设备没有通信。
* 它偶尔会在启动几秒后静默退出 → 用 `capture_keepalive.ps1` 看守（死了自动换文件续抓）。
* 设备地址会变（2 / 6），按 `usb.idVendor==0x054c` 或已知地址过滤。
* 致命教训：应用运行时会**独占**设备（INF 里 `Exclusive=1`），我们的工具会 `WinError 5` —— 先关应用。

### 12.2 学习/取码协议（已实测可用）

```
轮询取码： OUT 管道 00 -> OUT 管道 40 41 42 43 00 03 12 00 <槽位> -> IN 管道读
           回应 [len][00 01][码数据]   （len = 2 + 码长；0x14=20 → 18 字节码）
           空槽位回 01 06 / 或不应答
★ 读出会清空槽位 ★
```
实测：一次 `--scan` 就读到 3 个真实码（90 / 186 / 58 字节），随后又读到 50 字节的新码。
→ **接收功能完全可用，不需要官方应用。**

### 12.3 应用如何"注册遥控器"（dl_1.pcap）

```
1) 握手 00 -> magic 00 01 11 -> 04 00 01 0F FD
2) 轮询学习槽位：12 00 01 / 08 / 0B / 09 / 0A / 0C / 02 / 03 / 04 …（逐个取码）
3) 把取到的码写回设备码表（每槽连写 3 次）：
   OUT 40 41 42 43 <len> 10 <槽位2B> 90 01 <码数据>
      例：40 41 42 43 00 17 10 00 01 90 01 1a776ce00ba1e956193ca9e5dbaf78f946b9
      （len = 总长-6；payload = 0x01 + 取码时拿到的数据）→ 设备答 01 00 ✓
```

对比：我们按同样结构写回时，设备回 **`01 0A`（拒绝）**，即使结构与字节布局完全一致。
可能原因：需要某种会话状态（例如刚完成特定轮询、或必须写入"刚读出的那个槽位"），或数据需与设备内
容校验一致。**这是目前唯一未闭环的点。**

### 12.4 按键帧的应答语义（实测）

| 应答 | 观察 |
|---|---|
| `01 00` | 常见："已受理" |
| `01 03` | 只有键码 `0x14` / `0x1D` / `0x20` 出现（设备"认得"这些码） |
| `01 06` | 轮询空槽位 |
| `01 07` | 命令不支持/参数错（type 0x10 用错 flag、payload 包装错时出现） |
| `01 0A` | 写码表被拒 |

### 12.5 本轮新增工具

| 文件 | 作用 |
|---|---|
| `RE/tools/sird_learn.py` | 轮询槽位取学习码（`--learn/--slots/--replay`） |
| `RE/tools/sird_play.py` | 取码→装机→按键全链路（`--scan/--install/--press/--test/--live`） |
| `RE/tools/replay_capture.py` | 把抓包里的应用会话逐条重放（验证帧） |
| `RE/tools/dump_learn.py` | 按时间顺序整理抓包里的轮询/回应 |
| `RE/tools/capture_keepalive.ps1` | 看守式抓包（子进程死了自动重启续抓） |
| `RE/tools/probe_loopback.py` | 自环回测试（用设备自己的接收头验证发射） |
| 抓包留档 | `RE/capture/app_traffic3.pcap`（按键会话）、`dl_1.pcap`（注册+取码+写码表） |

### 12.6 时序真相与"写入被拒"的重新解释（本轮修正）

**发现 1：我们一直在用错的超时读设备。**
`sird_winusb.py` 初始化时把 WinUSB 的 `PIPE_TRANSFER_TIMEOUT` 策略设成了 2000 ms。
该策略**先于**我们自己的等待超时生效：任何超过 2 秒的设备回应都会被 WinUSB 直接判失败，
表现为"这个槽位没回应"。于是：

* 之前"读到槽位 0x07/0x1B/0x1D/0x1F 的码"其实是**前面轮询命令的迟到回应**（管道里排队）；
* "读出后槽位被清空"这个结论也因此不可靠。

已修：`pipe_read(timeout_ms=N)` 会先把该管道的策略超时放宽到 N+1000 ms。

**发现 2：轮询回应的真实延迟是 3~8 秒。**（dl_1.pcap 实测：43.99s 轮询 → 49.52s 才回；76.21→81.47；87.61→95.80）
应用自己也是这样等 5~8 秒才拿到码，然后才写回。

**发现 3：空槽位的回应是 `01 06`（也是迟到的），有码槽位回 `[len][00 01][码数据]`。**

**发现 4：全槽位扫描（0x00~0xFF，修正时序后）——设备里现在一个码都没有，全部回 `01 06`。**

**发现 5：写入被拒的真正原因不是格式。**
* 槽位里没有待写码时写入 → **立即**（0.04 s）回 `01 0A`；换个 flag/长度/槽位都是 `01 0A`（5 种变体全试过）。
* 应用在同一槽位"读到码之后"写回 → 0.25 s 回 `01 00` ✓
* 写回帧与我们构造的帧**逐字节同构**（`10 <槽位2B> 90 01 <数据>`，len = 数据+5）。

⇒ 结论：`type 0x10` 写入是"把刚从那台遥控器学到的码装进按键表"的**确认动作**，
设备要求该槽位处于"已交付待确认"的状态（槽内得有码）。**因此必须先真的接收到一个红外码。**

**发现 6：应用自己在抓包后半段（169 秒之后）的 20 多次写回也全都没有回应** ——
说明设备有流控/静默惩罚：连续写入过多就整段不理。写入要节流。

### 12.7 闭环工具 sird_teach.py（待用户配合）

```
python sird_teach.py --seconds 300 --press
```
轮询槽位 → 收到码立刻写回窗口内每个槽位 → 哪个回 `01 00` 就是装机成功 → 随即按键试探发射。
需要用户拿**任意红外遥控器**（电视/空调/风扇均可）对着适配器按键。

---

## 13. 里程碑：接收 → 装机 → 发射 全链路跑通（2026-09-23 凌晨实测）

### 13.1 实测记录（web 控制台日志，`RE/tools/sird_web.py`）

```
02:59:46 点击槽位 0x00 -> 开始学习（每 ~3.5s 轮询一次 12 00 00）
03:00:17 RX 74 00 01 31 86 65 93 ...  ← 设备回 114 字节！
03:00:20 ★ 槽位 0x00 读到码 114 字节
03:00:21 TX 40 41 42 43 00 77 10 00 00 90 01 <114 字节>
03:00:22 RX 01 00                      ← 写回被接受（首次拿到 01 00！）
03:00:24 ★ 装机成功
03:00:37 按 3 次键号 0x01 -> 每次 RX 01 00
          用户观察：适配器前窗的红外发射管**亮了 5~15 秒后自己灭**
```

结论：
1. **接收可用**：用户手机红外遥控的码被设备接收，通过 `12 00 <槽位>` 轮询取出（114 字节）。
2. **写入被接受的条件已被验证**：只要该槽位"刚交付过一个码"，同槽位写回就回 `01 00`
   （之前直接写空格位一律 `01 0A`）。⇒ 写入是"确认装机"，不是自由写。
3. **发射成立**：装了码之后按键，适配器红外发射管真的亮了（用户目视确认，前窗透出微红/紫光）。

### 13.2 按键语义（app_traffic3.pcap 逐帧对照）

| 帧 | 含义 | 设备回应 |
|---|---|---|
| `... 01 <ID2> <键号> 80 00 00` | 按下 | `01 00`（应用会话里全部是 01 00） |
| `... 01 <ID2> <键号> 00 00 00` | 松开 | 应用里也回 `01 00`；我们单发按下+松开时松开**没有回应** |

应用"按住"时的真实节奏（键 0x01）：2.9 → 4.3 → 5.5 → 7.0 → 7.9 → 8.8 → 12.2 秒，每 1.4 秒重发一次
`80` 帧，最后 12.4 / 12.8 秒补两个松开帧。其它按键（0x26/0x28/0x27/0x29/0x2a/0x78/0x1f/0x0b）
**只发按下的 `80`，从不发松开** ⇒ 单次按下即完整发射一次。

### 13.3 待解释：一次按下，发射管亮了 5~15 秒

* 现象：单发一条按下帧（无重复帧、无有效松开），灯亮好几秒到十几秒后自灭。
* 假说 A：学习到的码块**本身就长**（114 字节，普通遥控码只有 10~20 字节），
  设备把整段（含手机 App 发的重复帧）都录下来一起回放。
* 假说 B：`80` 表示"按住"，设备会持续重复直到松开；我们的松开帧被当无效（因为没进入 hold 状态）。
* 判别方法：换一个手机按键再学一次（码块长度不同），比较亮灯时长；若时长随码块长度变化 ⇒ 假说 A。
* 另需定出「槽位 ↔ 键号」对应：已知写槽位 0x00 后按 0x01 会亮 ⇒ 疑似 **键号 = 槽位 + 1**。
  控制台里新增「逐个键号发射一遍（看灯）」可一次性验证。

### 13.4 本轮新增资产

| 文件 | 说明 |
|---|---|
| `RE/tools/sird_web.py` | **web 控制台**（http://127.0.0.1:8765/）：点槽位学习、单槽读取、范围扫描、写入装机、按键发射、键号扫描、状态块监视、任意原始帧、USB 日志 |
| `RE/tools/learned/slot_00_1790103620.bin` | 实测学到的第一个码，114 字节 |
| `RE/tools/learned/slot_0B_1790103295.bin` | 另一个 18 字节的码 |
| 修正 | `sird_winusb.py`：`pipe_read` 按调用放宽 WinUSB 策略超时（原来固定 2000ms 导致读不到慢回应） |

### 13.5 回应语义定稿（实测）

| 回应 | 含义 | 证据 |
|---|---|---|
| `01 00` | 受理并发射（发射管会亮） | 键 0x01/0x0B/0x26 都是；用户目视确认发射管亮 |
| `01 03` | 拒绝：该键没有码 | 键 0x02/0x03/0x14 按下+松开都回 01 03，用户确认不亮 |
| （无回应） | 被接受的键，松开帧 = 空操作 | 键 0x01/0x0B/0x26 的松开都没回应；应用"按住后松开"时有回应 |
| `01 06` | 学习槽位空 | 轮询空槽位 |
| `01 0A` | 向"没有待确认码"的槽位写入被拒 | 直接写任意槽位 |

连按间隔测试（键 0x01，间隔 0.3/0.8/1.6/3.0/6.0/12.0 秒）全部 `01 00`
⇒ **`01 03` 不是"设备忙"，而是按键表里没有这个键的码**。

### 13.6 现在的疑问：为什么 0x04~0x13 这些"空槽位"对应的键也能发射？

已知：写槽位 0x0000 之后，键 0x01 能发射；但 0x04~0x13 也全部回 `01 00` 且用户看到灯亮，
而槽位扫描说那些槽位是空的。要么
(a) 写入槽位 0x0000 实际是"装了一份整机 profile"，大多数键都指向同一个码；
(b) 按键表与学习槽位不是同一套编号；
(c) 槽位扫描不可靠（回应延迟导致漏读）。
可用**反射自测**判定：让用户拿一张白纸/镜子放在适配器前 5cm，按一次键，
再扫学习槽位 —— 若收到码，说明发射的确实是红外且能被自己收回来，还能比较码长是否与装进去的一致。

---

## 14. 更正：槽位是主机（软件）指定的（实测判定）

### 14.1 决定性实验

前提：槽位 0x00 已被占用（114 字节码），不能再拿"第一个空槽位"解释。

```
03:23:32 TX 40 41 42 43 00 03 0c 48 90   -> RX 01 01   （进入学习模式，见 §14.3）
03:23:34 只轮询槽位 0x13（每 ~3.5s 一次）
03:23:52 RX 2c 00 01 284a6cd9 63 a7 63 56 33 ...        （42 字节码）
03:23:57 ★ 槽位 0x13 读到码 42 字节
03:24:59 TX 10 00 13 90 01 <42字节> -> RX 01 00          （写回装机被接受）
```

**结论：主机轮询哪个槽位，学到的码就进哪个槽位。** ⇒ 槽位命名空间由软件驱动，
我们的"点哪个格子就学进哪个格子"（也就是官方应用的做法）是正确的；
报告 §12.3/§13.6 里"码落到哪个槽位由设备决定"的说法**作废**。

补充证据：轮询回应里**从不包含槽位号**（第 2~3 字节恒为 `00 01`），
所以只有主机知道自己在问哪个槽位 —— 与"主机驱动"一致。

### 14.2 预测失败记录（如实保留）

曾预测「键号 = 槽位 + 1」。写入槽位 0x13 成功后按键 0x14：

```
按 0x14 -> 01 03   （仍然"无码"）      <= 预测失败
按 0x01 -> 01 00
按 0x0B -> 01 00
```

⇒ 键号与学习槽位不是简单偏移关系。新的怀疑：键 0x01/0x0B 能发射，
可能是设备里**还留着官方应用当年装进去的码表**，与我们这次的写入无关。
要分辨只能靠第二台适配器当接收裁判（见 §13 计划）。

### 14.3 新发现：`type 0x0C` = 进入学习模式

应用学习会话（learn_final.pcap）在读码前发过一条我们从未发过的命令：

```
55.49s TX 40 41 42 43 00 03 0C 48 90  -> RX 01 01
```

复现与探测结果：

| 发送 | 回应 | 说明 |
|---|---|---|
| `0C 48 90` | `01 01` | 应用中出现的原样命令 |
| `0C 00 00` | `01 01` | 参数**不被校验** |
| `0C 0F 90` / `0C 01 01` / `0C 48 91` | `01 01` | 同上 |
| `0C`（len=0） | `01 07` | 只校验**长度必须为 2** |

⇒ `0C` 是"进入学习模式"的开关，两个参数字是固定填充。

### 14.4 顺带修正：清管道时不能白丢码

发现有一条 18 字节的码在"清空管道"时被当迟到回应丢弃。
`sird_web.py` 的 `drain()` 已改：带数据的迟到回应会另存为 `learned/unclaimed_*.bin`
并在日志里用 `!!` 提醒（回应里没有槽位号，只能靠逐个槽位点一遍来确认归属）。

---

## 15. 发射时长由"装进去的码块长度"决定（实测，用户目视）

用户的核心诉求："发射能不能只发一次，不要一直发"。

### 15.1 实验与结论

| 装进去的码 | 大小 | 用户观察 |
|---|---|---|
| 03:00 装的那个（**按住遥控器**学到的） | 114 字节 | 亮 5~15 秒后自己灭（"亮了半天"） |
| 03:34 装的（**极快点一下**学到的） | 18 字节 | **一闪**（一次短发射） |

对照实验（同一键 0x01，装的是 18 字节短码）：
* A 只按下、完全不掐停 → 一闪
* B 按下后 2 秒发 `flush`(控制请求 0x12) → 一闪
* C 按下后 0.2 秒发 `flush` → 一闪

⇒ **`flush` 不是"刹车"，不影响发射时长**（三个都一样）。
⇒ **发射时长 ≈ 学到的码块长度**：手机红外 App 一次点按发出的重复帧越多，
设备录下的码块越大，回放就越久。

**实用结论：想要"只发一次"，学习时用最快的点按（拿到 18 字节级短码）即可。**
控制台已新增「单次发射（只发一次）」按钮（只发一条按下帧，不补松开、不重发）。

### 15.2 现象记录：出现过"一直亮不灭"

03:36 前后用户观察到发射管**持续亮着不灭**（不是"亮一会儿自行熄灭"）。
随后依次尝试：补发松开帧 0x15 / 补发松开帧 0x01 / `flush` / 按下再松开 / 重新握手 / 重新初始化寄存器，
用户报告灯在 `flush`（第 3 步）之后熄灭。但后续对照实验（§15.1）显示 `flush` 与时长无关，
所以"一直亮"更可能是当时装的码更长（或设备进入了持续重发状态），**这一点仍未定论**。

### 15.3 仍未定论：键号 ↔ 槽位

| 键号 | 对应槽位有码？ | 按下回应 | 发射管 |
|---|---|---|---|
| 0x01 / 0x0B / 0x13 | 有 | 01 00 | 亮 |
| 0x04 / 0x15（今天新学到、从未写回） | 有 | 01 00 | 亮 |
| 0x02（槽位有 130 字节超长码）/ 0x03（18 字节） | 有 | 01 03 | 不亮 |

键号 0x04/0x15 的槽位是**今天才学到、我们从未写回装机**的，却能发射；而 0x02/0x03 不行。
⇒ 要么"装机"这一步有额外语义（应用当年每槽连写 3 次），要么超长码会被拒。
**最终判定需要第二台适配器当接收裁判。**

---

## 16. 大码库：从应用里整套导出（SQLite）

### 16.1 库是什么

应用自带的 UEI QuickSet 码库，由**原生** DLL `Sony.VAIO.VAIORemotecontrol.IRLayer.dll` 提供，
导出 `QS_*` 一整套 C 接口（不是托管程序集，dnSpy 看不了；`VAIO Remote control.exe` 才是托管的）。

```
QS_start("cmd.conf") -> QS_retrieve_device_types() -> QS_get_device_type_name(i)
  -> QS_retrieve_brands(type, filter) -> QS_get_brand_name(j)
  -> QS_retrieve_codesets_by_brand(0) -> QS_get_codeset_name(k)
  -> QS_get_codeset_binary(name, &buf, &size) -> QS_stop()
```

应用用的库版本：`v1.9.7.1_RC1`，本地库 `Sony_Android_database_v3.2_sonytab`。

### 16.2 全库规模（实测清点，7.4 分钟）

| 设备类型 | 品牌数 | 码表数 |
|---|---:|---:|
| TV | 1762 | 11044 |
| Satellite/DSS | 1402 | ~4700 |
| DVD | 1167 | 4921 |
| VCR | 1045 | 3609 |
| Receiver, Misc Audio | 655 | 3040 |
| Cable, IPTV | 608 | 1446 |
| Video Accessory | 407 | 714 |
| CD | 304 | 925 |
| Amplifier | 273 | 510 |
| Home Control | 136 | 251 |
| **合计** | **7759** | **31876** |

单份码表平均约 107 字节（`T4090` 那份 116 字节），全库去重后预计仅几 MB。

### 16.3 工具

| 文件 | 用途 |
|---|---|
| `RE/tools/qs_db.py` | **导出到单个 SQLite**（`--db`），带 0.5 秒刷新的实时进度行；另有 `--stat/--find/--get` 查询；`INSERT OR REPLACE` 可重复跑 |
| `RE/tools/qs_count.py` | 只清点不导出（测规模/测速度） |
| `RE/tools/qs_dump.py` | 早期单份提取工具（`--type/--brand/--index/--out`） |

⚠️ **两个坑**（都踩过）：
1. `QS_*` 是**全局单例状态**：`QS_retrieve_brands()` 之后必须**立刻**把品牌名全收集到 Python 列表，
   否则遍历中再调一次 `QS_retrieve_brands()` 会覆盖全局列表，`QS_get_brand_name(j)` 取到脏数据（表现为卡死）。
2. Python 输出重定向时是**块缓冲**：脚本必须用 `python -u` 跑，否则看不到进度（表现为"好像卡住了"）。

### 16.4 还要解决的一步：怎么把库里的码表"装"进设备

`RegisterRemoteControl(DeviceInfo)` 是应用装机时的入口（`SDKManager.cs:329`），
它把 `RegistedRemoteControlInfoStru`（类别/地区/品牌/型号/图标/遥控器ID/手势/主题…）
交给原生 `IRLayer.RegisterRemoteControl()`，由原生层查库并推给设备 —— 这一步在原生 DLL 里。
可行的两条路：
1. **抓包法**（已验证可行）：跑官方应用新增一个品牌的遥控器，用 USBPcap 抓下整段 USB 流量，
   得到"码库装机"的帧序列（疑似 `type 0x22` 分块上传），然后自己复刻。
2. 直接调 `IRLayer.dll` 的 WinRT 方法（需要 WinRT 激活，比 C 接口麻烦）。

### 16.5 导出完成（实测）

```
全部 10 类：品牌 7759 / 码表 31876
原始二进制 3,794,784 字节（3.62 MB）
按内容 SHA1 去重后：11643 份 / 1,386,996 字节（1.32 MB）   ← 去重率 3.2:1
数据库文件 D:\harness\SonyIR\VGP-URM10\qsdb.sqlite ≈ 7.0 MB（VACUUM 后，含索引）
```

校验：库里的 `T4090`（Sony TV）与最早用 `qs_dump.py` 手工抽出的
`VGP-URM10\codeset_sony_tv_0.bin` **逐字节相同** ✓（116 字节，头 `00 02 a2 43 2e 03 97 6a …`）。

查询示例：
```
python -u qs_db.py --db ... --find Sony --types TV
  TV  Sony  #0 T4090 116 B / #1 T4091 116 B / #2 T4092 148 B / #3 T4093 196 B ...
python -u qs_db.py --db ... --get T4090 --out sony.bin
```

Sony 电视在库里是 `T4090~T4095` 等一组（116~220 字节），说明**一份码表就是一个完整遥控器**
（几十个按键）—— 这正是"装进设备就能当万能遥控器"的东西。

---

## 17. IRLayer.dll 的真实结构：码库 API ≠ 设备 I/O

### 17.1 导出表（51 个具名导出）

```
DllGetActivationFactory / DllCanUnloadNow          ← 说明它同时是个 WinRT 组件
QS_start / QS_stop / QS_getVersionString / QS_getLocalDBVersionString
QS_retrieve_device_types / QS_retrieve_brands / QS_retrieve_codesets_by_brand / QS_retrieve_models
QS_get_device_type_name / QS_get_brand_name / QS_get_codeset_name / QS_get_model_name
QS_get_codeset_total / QS_get_brands_total / QS_get_models_total
QS_get_codeset_binary(name, void**, uint*)        ← 取码表二进制
QS_send_codeset(int index, int flag)              ← 名字很像"装机"，但见 17.2
QS_send_codeset_by_name(const char* name, int flag)
QS_status_codeset_sent() / QS_get_last_error_* / QS_Option_* / QS_query_mode_*
QS_online_*（线上库）/ QS_CEC_* / QS_EDID_*
```

### 17.2 重大否定结果：`QS_send_codeset*` **不碰 USB**

实验：让 web 控制台**独占**适配器（自测 `CreateFileW` 已返回 `WinError 5`），此时再调：

```
QS_send_codeset_by_name('T4091', 0)  ->  返回 0 (success)，用时 0.0 秒
QS_status_codeset_sent()             ->  指向字符串 'T4091'
```

⇒ `QS_send_codeset*` 只是把"当前码表"记在**库内部状态**里，**没有做任何设备 I/O**。
整族 `QS_*` 是**纯码库引擎**（查品牌/型号/取二进制），设备通信不在里面。

### 17.3 设备 I/O 在同一个 DLL 的 WinRT 类 `CIRLayer` 里

`DllGetActivationFactory` 暴露 `CIRLayer`（应用 C# 里的 `_IRLayer`）。winmd 里的完整方法表：

```
ConnectDevice / DisconnectDevice / SetRegion / IsIRDeviceConnnected / GetIRDeviceType
RegisterIRDeviceChangeCallBack / RegisterDevicePermissionChange
GetAllDeviceType / GetAllDeviceBrandByType / GetDeviceModelsByTypeAndBrand
RegisterRemoteControl          ← 从码库装一整台遥控器（设备 I/O 在这里）
SelectRemoteControlById / GetRemoteControlList / GetRemoteControlSettingById
UpdateRemoteControlSetting / UpdateRemoteControlOrder / DeleteRemoteControlById
GetRemoteControlLayoutById     ← 返回每个按键的信息表
DeleteButtonCommandById / UpdateRemoteControlButtonText
EnterEditMode / ExitEditMode   ← 可能就是我们抓到的 0C 48 90
SendKeyCode / SendKeyCodeContinuously
LearnDeviceButtonCodeAsync / CancelOperationById / CancelAllOperations
AddMacro / UpdateMacroFunctionById / DeleteMacroById / GetMacroList / GetMacroById / UpdateMacroNameById
```

**重要数据结构**：`UILayoutInformationStru` 含
`iLayoutID / iKeyID / strLearnedData / strIRCode / bIsLearned / bIsHaveCommand / strModifyName`
⇒ 每个按键的**学习数据**和 **IR 码**都能经 API 读回（比我们轮询槽位靠谱）。

**`ErrorCodeEnum`（设备侧错误语义，直接抄下来）**：

```
enError_InvalidDeviceCode / InvalidDeviceType / InvalidKeyCode
enError_BadFRDA / OutOfFRDAMemory                     ← FRDA = UEI 芯片 Flash/FRAM 数据区
enError_UEITimeOut / UEIDataPacketFormatError / UEIDownloadIDAleadyExixted
enError_UEILowVoltageFDRAAccessError / UEIInvalidLearnCodeID / UEIReturnCheckError
enError_DeviceNotConnected / DeviceAccessDenied / DeviceNoIOHandle / DeviceAleadyInit / DeviceWaitTimeOut
enError_CommandInvalidarg / CommandBufferTooSmall / CommandInvalidCancelHandle
enError_CommandRequestFailed / CommandRequestCanceled
enError_PermissionOff / ExpiredDriver / InternalNoDriver / ExternalNoDriver
```

`UEIDownloadID...` 说明"往设备里下码表"是设备的正式机制（下载 ID + FRDA 存储）。

### 17.4 要打通"码库 → 设备"的三条路

| 方案 | 做法 | 成本 |
|---|---|---|
| **A 抓包法（推荐）** | 官方应用"添加设备"→ USBPcap 抓整段流量 → 复刻帧序列 | 已验证的工具链，十几分钟，**结论确定** |
| B C#/CsWinRT 宿主 | 用 .NET 10 + CsWinRT 从 winmd 生成投影，直接调 `CIRLayer` | 需要处理 WinRT 激活/投影，工作量中等 |
| C C++/WinRT 宿主 | `cppwinrt.exe` 生成头 + MSVC 编译 | 需要 MSVC，最重 |

本机已有：.NET 10 SDK、dnSpy、capstone、USBPcap —— 方案 A 与 B 都可行。

---

## 18. ★ 最后一公里打通：从码库装机（抓包实测）

### 18.1 抓包现场

用户用官方应用「添加设备」加了一台 **Sony 电视**（随后又删掉了），
用 `USBPcapCMD -d \\.\USBPcap2 -o add_device_1.pcap -b 4096 -A --inject-descriptors` 抓下全程。
适配器（VID 054C / PID 0883，本次 addr=6）的全部流量：

```
 0.06s TX  00                                     ← arm（每条命令前必有）
 0.17s TX  40 41 42 43 00 01 11                   ← 握手
 0.17s RX  04 00 01 0f fd                         ← 设备/profie ID = 0x0ffd
 8.13s TX  00
 8.24s TX  40 41 42 43 00 03 0c 0f fd             ← type 0x0C + profileID = 进/出编辑模式
 8.30s RX  01 00
10.72s TX  00
10.83s TX  40 41 42 43 00 01 11                   ← 再握手
10.84s RX  02 00 00                               ← 注意：这次回的是 02 00 00
10.88s TX  00
10.99s TX  40 41 42 43 00 c7 22 0f fd <196 字节>  ← ★★★ type 0x22 = 下码表
11.23s RX  01 00                                  ← 受理
11.23s TX  00
11.34s TX  40 41 42 43 00 03 02 0f fd             ← ★ type 0x02 = 查询键表
11.38s RX  43 00 01 <64 个键号>                    ← 该 profile 可用的按键清单
17.80s TX  00
17.89s TX  40 41 42 43 00 03 0c 0f fd             ← 再次 0x0C
17.96s RX  01 00
```

### 18.2 帧格式（已用代码逐字节复现，完全一致）

```
下码表：  40 41 42 43 | len | 22 | <profileID 2B> | <码表二进制>
          len = 码表长度 + 3      例：196 字节码表 -> len = 199 = 0x00C7，整帧 205 字节
查询键表：40 41 42 43 | 00 03 | 02 | <profileID 2B>
          -> 43 00 01 <N 个键号>   （N = len-3；实测 N=64）
编辑模式：40 41 42 43 | 00 03 | 0C | <profileID 2B>   -> 01 00
```

**校验**：用 `codeset T4093` 构造的帧与抓包帧 `cap == ours` → **True**（205 字节完全一致）；
键表查询帧也一致 ⇒ 我们的实现可以不用硬件先验证正确性。

### 18.3 两个旧谜团同时解开

1. **`0C 48 90` 之谜**：`type 0x0C` 后面两字节不是固定填充，而是 **profileID**。
   本次是 `0c 0f fd`（= 0x0ffd），学习会话里是 `0c 48 90`（= profile 0x4890）⇒ profile ID 会变。
2. **`01 03` 之谜**：`type 0x02` 返回的键号清单就是"这个 profile 有哪些键"。
   实测对照（键在清单里 → `01 00`；不在 → `01 03`）：

   | 键号 | 在清单里 | 按键回应 |
   |---|---|---|
   | 0x02 / 0x03 / 0x14 | ❌ | `01 03` |
   | 0x04 / 0x0B / 0x26 / 0x78 | ✅ | `01 00` |

### 18.4 库与设备的一致性

抓包里那 196 字节码表载荷，与 `VGP-URM10\qsdb.sqlite` 里的
**`TV / Sony / T4093`（196 字节）逐字节相同** ⇒ **我们导出的库就是应用用的那个库**。

⇒ 至此"万能遥控器"链路完整：
**qsdb.sqlite（7759 品牌 / 31876 份码表）→ `type 0x22` 下发 → 设备发射**，
全程可以用我们自己的工具完成，不需要官方应用、不需要真电视。

### 18.5 删除（待补）

应用侧删除走 `DeleteButtonCommandById(deviceId, buttonId)` / `DeleteRemoteControlById(id)`，
本次抓包的删除动作**没录到**（USBPcapCMD 有 4KB 缓冲，进程被结束时缓冲内容丢失）。
两条待办：
1. 重新抓一次删除动作（抓包时**不要中途杀进程**，让它自然结束或先 `-b` 调小缓冲）；
2. 或用类型扫描法：遍历 `type 0x00~0x30` + profileID，看哪些回应不是 `01 07`（不支持），
   即可定位"删除按键/删除遥控器"的命令号。

---

## 19. ★ profile 机制完全解开（抓包 + 实测矩阵）

### 19.1 握手回应 = profile 列表

```
02 00 00                              0 个 profile
04 00 01 0f fd                        1 个: 0ffd
06 00 02 0f fd 08 32                  2 个: +0832
08 00 03 0f fd 08 32 03 25            3 个: +0325
0a 00 04 0f fd 08 32 03 25 7f fb      4 个: +7ffb
```
格式 `[总长][00][个数][ID 2B]...`。**最多 4 个 profile。**

### 19.2 命令表（全部实测）

| 命令 | 帧 | 回应 | 含义 |
|---|---|---|---|
| 握手 | `00 01 11` | `[len] 00 <n> <ID>...` | 报告 profile 列表 |
| 下码表 | `22 <profile2B> <码表>`（len = 码表长+3） | `01 00` | 装码表（新建 profile） |
| 查键表 | `02 <profile2B>` | `[len] 00 01 <键号...>` | 该 profile 的可用键号 |
| **删除 profile** | `0C <profile2B>` | `01 00` | **释放槽位**（列表变短）|
| 按键 | `01 <profile2B> <键号> 80/00 00 00` | `01 00` | 发射/松开 |
| `0F <profile2B>` | | `01 00` | 疑似登记/创建（对装机无帮助）|
| `03/04 <profile2B>` | | `01 01` 或 `03 00 <ID>` | 未知 |
| `0B`（无参） | | `09 00 "25242541"` | 返回 ASCII，疑似序列号/版本 |
| 未知 type | | `01 07` | 命令不支持 |

### 19.3 profile ↔ 码表 是**持久绑定**

| 试验 | 结果 |
|---|---|
| `0ffd <- T4093`（应用原始配对） | `01 00` ✓（再装一次回 `01 08` = 已是同一份）|
| `0ffd <- T4091`（同 profile 换表） | `01 01` ✗ |
| `0832 <- T2098`（Daewoo 原配对） | `01 00` ✓ |
| `0832 <- T4090`（换表，即使先 `0C` 删除） | `01 01` ✗ |
| `0325 <- T0805` / `7ffb <- R4091`（原配对） | `01 00` ✓ |
| 全新 ID `1000/1234/5678/9999` | `01 01` ✗（第 5 个 profile 也是 `01 01`）|

⇒ ① 最多 4 个 profile；② 一个 profile 只认它的原配码表；③ **全新 ID 不被接受**
（设备只认得它历史上见过的 ID；从全部抓包里挖出来的是
`0325 053b 0832 0ffd 4890 7ffb` 这 6 个）。

`01 08` = "该 profile 已装有同一份码表，无需重复安装"。

### 19.4 应用"删除遥控器"不改设备

用户在应用里删除遥控器时抓包，适配器**没有任何批量传输**（整份 pcap 只有 130 个包，
全是设备枚举）⇒ 应用的删除是**纯软件侧**（改它自己的 XML/配置），设备里的 profile 与绑定都留着。

### 19.5 结论与两条继续的路

**已能完全自主完成的**：用已知的 6 个 profile ID 装配对码表、查询键表、发射按键、删除 profile。
**还不能的**：把"任意品牌任意码表"装进设备（需要新的 profile ID）。

| 路线 | 说明 |
|---|---|
| A 用应用"开槽" | 让官方应用注册你想用的品牌（每次注册会分配它认得的 ID 并成功装机），之后用我们的工具查键表/发射/删除 —— 4 个槽位轮换 |
| B 找"登记新 profile"的命令 | `0x0F` 可疑但未成功；也可能设备认的 ID 名单存在控制请求写的 16 字节寄存器里（0x13/0x14），或与 ID 空间/校验有关，需继续逆 |

### 19.6 工具

| 文件 | 用途 |
|---|---|
| `RE/tools/sird_universal.py` | 万能遥控器流程：列 profile / 装码表 / 查键表 / 删除 / 发射 |
| `RE/tools/probe_profile_bind.py` | profile 绑定判别矩阵 |
| `RE/tools/probe_binding2.py` | 配对模型验证（P1~P8） |
| `RE/tools/probe_delete.py` | 用"profile 列表变短"当探针找出 `0C` = 删除 |
| `RE/tools/probe_create.py` | 尝试创建新 profile 的判别实验 |

---

## 20. ★★★ 终极答案：profile ID = 码表编号（万能遥控器达成）

### 20.1 假设的由来

应用注册的三台设备，profile ID 与它装的码表编号一一对应：

| profile ID | 十进制 | 应用装的码表 |
|---|---|---|
| `0x0ffd` | 4093 | **T4093** |
| `0x0832` | 2098 | **T2098** |
| `0x0325` | 805 | **T0805** |
| `0x7ffb` | 32763 | R4091（唯一对不上的，待查）|

### 20.2 决定性实验（实测）

| 试验 | 结果 |
|---|---|
| `T4090`(116B) → profile `0x0FFA`(=4090) | **01 00 ✓** |
| `T4091`(116B) → profile `0x0FFB`(=4091) | **01 00 ✓** |
| `T4092`(148B) → profile `0x0FFC`(=4092) | **01 00 ✓** |
| `T4091` → profile `0x0FFA`(=4090) | `01 01` ✗ ← 反例，编号与数据不符 |
| `T0090`(52B, Samsung/RCA) → `0x005A`(=90) | **01 00 ✓** 跨品牌 |
| `T0340`(44B, Panasonic) → `0x0154`(=340) | **01 00 ✓** |
| `T0429`(68B, LG) → `0x01AD`(=429) | **01 00 ✓** |

⇒ **装码表帧里的 2 字节必须是该码表的编号**。设备能校验"编号 ↔ 数据"是否匹配
（编号并不以明文出现在码表二进制里；所有品牌码表共享同一段 19 字节包头，
所以那是包装/校验结构，设备用它反推归属）。

### 20.3 那么 profile 到底是什么？

**profile = 设备里存放"一份完整遥控器"的槽位**，以**码表编号**为索引：

* 每份码表 = 一整套遥控器（几十个按键号 → 各自的发射码）；
* 设备**最多存 4 个** profile（握手回应就是这 4 个槽位的列表）；
* `22 <编号> <码表数据>` 把某编号的码表装进对应槽位；重复装同一份回 `01 08`（已存在）；
* `02 <编号>` 查询该遥控器有哪些按键；
* `0C <编号>` 删除该槽位（释放位置）；
* `01 <编号> <键号> 80/00 00 00` 按该遥控器的某个键发射；
* 编号 ↔ 数据不匹配（或数据被改坏）→ `01 01` / `01 07`。

### 20.4 最终能力（实测）

```
qsdb.sqlite（7759 品牌 / 31876 份码表）
  → 取任一码表 -> profile ID = 其编号
  → 22 裝机（满了先 0C 删一个）
  → 02 查键表（知道有哪些键）
  → 01 <编号> <键号> 80 00 00 发射
全程不需要官方应用、不需要真电视、不需要手机。
```

实测跑通（Samsung/RCA T0090，自动推导 ID + 自动腾位）：
```
当前 profile：0FFD 0325 0FFA 01AD
自动推导 profile ID = 90 (0x005A)
profile 已满(4)，先删掉 01AD 腾位置
装机 -> 01 00 ★ 成功
可用键号 5 个：04 05 06 07 08
发射 04/05/06/07/08 -> 全部 01 00 ★
```

### 20.5 工具

| 文件 | 用途 |
|---|---|
| `RE/tools/sird_universal.py` | **万能遥控器**：`--list` 看 profile、`--name T4090 --press-sweep` 装机+发射、`--delete 0x0ffd` 删槽位；自动用编号当 profile ID、满了自动腾位 |
| `RE/tools/sird_web.py` | Web 控制台「码库装机」面板同样已接入该逻辑 |
| `RE/tools/probe_id_is_codeset.py` | 编号假设的验证脚本 |

### 20.6 最终验证（用户目视确认）

```
05:29:32  取码表 T0090（Samsung/RCA 电视，52 字节）
          自动推导 profile ID = 90 (0x005A)   ← 与码表编号一致
05:29:33  TX 40 41 42 43 00 07 01 00 5a 04 80 00 00  ->  01 00
05:29:36  ... 键号 05 ...                             ->  01 00
05:29:39  ... 键号 06 ...                             ->  01 00
05:29:42  ... 键号 07 ...                             ->  01 00
05:29:45  ... 键号 08 ...                             ->  01 00
05:29:48~05:30:00  第二轮 5 个键                       ->  全部 01 00
用户确认：适配器的红外发射管【闪了 10 下】✓
```

⇒ **"码库 → 装机 → 发射"全链路端到端验证通过**，且完全脱离官方应用。

### 20.7 最终结论：profile 是什么

**profile = 适配器内部持久保存的一个"整台遥控器"槽位，以码表编号为索引。**
* 设备最多 **4 个** profile（握手回应就是这 4 个槽位的当前列表）；
* 每个槽位存一份码表（= 一整套遥控器的所有按键码）；
* 装：`22 <编号> <码表>`；查：`02 <编号>`；删：`0C <编号>`；发：`01 <编号> <键号> 80 00 00`；
* 编号必须与码表数据匹配，否则 `01 01`；数据被改坏是 `01 07`；重复装同一份是 `01 08`；
* 掉电不丢（多次会话后列表仍在），是设备内的非易失存储。

---

## 21. 纯 WebUSB 版 + 容量与回应码修正（实测）

### 21.1 WebUSB 可行性：已验证可以

用户提问"理论上能不能只靠 WebUSB 工作"。结论：**能，而且已经跑通**。

我们用的传输全在 WebUSB 的 API 面内：
* 厂商控制请求（`0x00` 初始化 / `0x1E` / `0x19` / `0x12` flush）→ `controlTransferOut({requestType:'vendor'})`
* 批量端点 0x01 OUT / 0x82 IN → `transferOut(1, …)` / `transferIn(2, …)`

前提在这台机器上已满足：设备由 **WinUSB** 绑定（Sony 的 INF 在 Win8.1+ 就是如此）、
单一 interface、vendor class `0xFF`、页面走 `http://127.0.0.1` 可信来源。

实测日志（Edge）：
```
SYS 已连接 IR Adapter  IN=0x2 OUT=0x1
TX 40 41 42 43 00 07 01 00 5a 04 80 00 00
RX 01 00                            ← 用户确认：红外发射管闪了，按下立即生效
```

### 21.2 网页版资产

```
RE/tools/webusb_poc.html        10 KB    最小 PoC（连接/握手/装机/发射/原始帧）
RE/tools/web/universal.html     14 KB    完整网页版（码库搜索 + 装机 + 按键面板 + profile 管理 + 断开）
RE/tools/web/qs_index.json     1.23 MB   31876 条索引 [类型,品牌,名称,偏移,长度]
RE/tools/web/qs_blobs.bin      1.32 MB   11643 份去重码表二进制
RE/tools/web/qs_meta.json      0.2 KB    统计
RE/tools/qs_webexport.py                 生成上面三个库文件的脚本
```
零依赖、零后端：一个静态目录即可（`python -m http.server 8899 --directory RE/tools`）。

### 21.3 修正一：**装机回应码的完整语义**

| 回应 | 含义 |
|---|---|
| `01 00` | 装进**已存在**的 profile，成功 |
| **`01 80`** | **新建 profile 并装入，成功**（0x80 位 = 新建）——之前误判为失败 |
| `01 08` | 已装过同一份码表（无变化） |
| **`01 05`** | **容量满**（第 47 个 profile 时出现） |
| `01 01` | 编号与数据不符 / 被拒 |
| `01 07` | 帧格式错、或数据被改坏（改一个字节即触发） |

### 21.4 修正二：容量是 **46 个 profile**（不是 4 个）

之前"4 个上限"是**误判**——那只是当时的数量。实测连续装机：

```
起始  6 个 -> 8 个(3M/888/A-Mark/A.R.Systems/ADL/AEG/AG Electronics/AGATH)
          -> 14 个 -> ... -> 46 个（全部回 01 80 = 新建成功）
第 47 个（Albatron T0700）-> 01 05 = 容量满
```

⇒ 设备可同时保存 **46 套完整的遥控器**（每套含全部按键码），且掉电不丢。
握手回应可一次列出全部 46 个 profile ID。

### 21.5 新增工具

| 文件 | 用途 |
|---|---|
| `RE/tools/probe_0180.py` | 查清 `01 80` 语义（对每个 profile 查键表 + 试按） |
| `RE/tools/probe_max_profiles.py` | 探测 profile 容量（逐个装不同品牌码表直到失败） |
| `RE/tools/probe_web_install.py` | 复现网页装机（编号 3183/2449），用于对照 |

### 21.6 网页版踩过的坑

1. 握手帧必须是 `40 41 42 43 00 01 11`（len=1，body 只有 `11`）。写成 `…00 03 00 01 11` 会被回 `01 07`，
   进而导致"读不到 profile 列表 → 误判设备是空的 → 不做腾位 → 装机撞容量"的连锁问题。
2. WebUSB 是**独占**的：页面 claim 之后 Python 工具会 `WinError 5`，所以网页加了「断开设备」按钮
   （`releaseInterface` + `close`）；刷新页面同样会释放。

---

## 22. ★ 更正：WebUSB 仍然需要"驱动"（WinUSB 绑定）

### 22.1 之前说法的错误

§21.1 说 WebUSB 版是"零驱动"，**措辞错误**。准确说法是：
**不需要厂商专有驱动/厂商软件；但设备必须被通用驱动 WinUSB 接管，这一步无法省略。**

### 22.2 本机的实测证据

```
注册表 HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_054C&PID_0883\0082BA65
    Service       = WINUSB
    ClassGUID     = {88bae032-5a81-49f0-bc3d-a4ff138216d6}   (WinUSB 设备类)
    DeviceDesc    = @oem242.inf,…;Sony IR Remote Control
    DeviceInterfaceGUIDs = {AC2C0F91-97D5-452D-8F89-E055C8C498A4}   (Sony INF 注册)
    InfPath       = (空；绑定来自 oem242.inf = Sony 的 SIRD.inf)
    CompatibleIDs = USB\COMPAT_VID_054C&Class_FF&SubClass_00&Prot_00
                    USB\COMPAT_VID_054C&Class_FF … USB\Class_FF
                    ★ 没有 USB\MS_COMP_WINUSB
```

Sony 的 `SIRD.inf`（安装后即 `oem242.inf`）：
```
[Standard.NTamd64.6.2] / [Standard.NTamd64.6.3]
    Include = winusb.inf
    Needs   = WINUSB.NT
```

⇒ **本机之所以"不用额外装东西"，是因为用户当初装过 Sony 的驱动包**，
它的 INF 在 Win8.1+ 上选择了 in-box 的 WinUSB（而不是 `SIRD.sys`）。

### 22.3 关键点：设备**没有**自我声明 WinUSB

`CompatibleIDs` 里没有 `USB\MS_COMP_WINUSB` ⇒ 设备未提供 MS OS 描述符。
所以**全新 Windows（未装 Sony 驱动）上，Windows 只会看到未知厂商类设备，不会自动绑 WinUSB，
浏览器的 WebUSB 设备框里也就看不到它** ⇒ 必须用 INF 或 Zadig 手动绑 WinUSB。

（若设备在描述符里声明 `WINUSB` 兼容 ID，Windows 8+ 才会自动绑定、真正"零安装"。这台不是。）

### 22.4 各平台要求（结论）

| 平台 | 要求 |
|---|---|
| Windows | **必须**有 WinUSB 绑定（INF 或 Zadig）；Chrome/Edge 才行 |
| Linux | 不需要内核驱动，但需要 **udev 规则**给权限；Chrome 可直接 claim 厂商类接口 |
| macOS | 不需要驱动、不需要规则 |
| Android | Chrome 支持但受系统 USB 权限限制 |
| Firefox / Safari | **不支持 WebUSB**，装什么都没用 |

---

## 23. 前端内置"微型驱动"安装助手

考虑到 WebUSB 在干净 Windows 上必须先绑 WinUSB（§22），网页版里加了驱动助手面板：

| 网页按钮 | 产出/动作 |
|---|---|
| ① 下载驱动 INF | `web/vgp-urm10-winusb.inf`（2 KB，只有 `Include=winusb.inf` + `Needs=WINUSB.NT` + 接口 GUID 注册） |
| ② 下载一键安装脚本 | `web/install-winusb.bat`：检测同目录 INF → `net session` 检测管理员 → `Start-Process -Verb RunAs` 自提权 → `pnputil /add-driver … /install` → 失败时提示退路 |
| ③ 复制手动命令 | `pnputil /add-driver "%USERPROFILE%\Downloads\vgp-urm10-winusb.inf" /install` |
| ④ 自检 | `navigator.usb.getDevices()` 列出已授权设备；授权框为空即可判定"驱动未绑"，并给出注册表自查命令 |

要点：
* 浏览器无法直接安装内核驱动（安全限制），所以只能"下载 + 提示 + 自检"，提权由 `.bat` 完成；
* `.bat` 保持**纯 ASCII**（避免中文编码导致的批处理解析问题，这个坑本项目踩过多次）；
* INF 不含任何厂商内核驱动，只把设备交给 Windows 自带的 `winusb.sys`；
* 签名提醒：x64 Windows 可能拒绝未签名 INF，退路是装 Sony 原厂驱动包或使用 Zadig。

### 23.1 简化版：一个按钮 + 一个弹窗

用户反馈"⑥ 驱动"面板太复杂。改为：
* 「连接设备」旁边只放一个 **「找不到设备？」** 按钮；
* 点击弹出对话框，内含三个下载项和一个自检提示：
  * ① **单文件脚本** `web/install-winusb.ps1`（3 KB，**自包含**：脚本内部就是一个 here-string 形式的 INF，
    写出到 %TEMP% 后自提权并调用 `pnputil /add-driver … /install`；失败时提示退路）
  * ② **全量安装包** `web/Sony_IR_driver_EP0000311568.exe`（10.5 MB，Sony 原厂驱动包，最稳）
  * 只要 INF `web/vgp-urm10-winusb.inf`（2 KB）+「复制运行命令」
* 弹窗打开时顺手用 `navigator.usb.getDevices()` 自检，直接告诉用户"是否真的需要装驱动"。

（`.bat` 版本保留在目录里备用；单文件 `.ps1` 更方便，因为它不需要 INF 在旁边。）

### 23.2 再简化：`irm … | iex` 一行式（不再下载脚本文件）

用户建议：脚本不必落盘 —— 页面用 `document.location` 拼出脚本 URL，
「复制安装命令」直接给一行 `irm … | iex`，只保留两个按钮。

弹窗最终形态：
```
① 复制安装命令（一行搞定）   →  powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:VGP_URL='<脚本URL>'; irm $env:VGP_URL | iex"
② 下载完整安装包（10 MB · Sony 原厂）  →  Sony_IR_driver_EP0000311568.exe
```

脚本端配合改动（`web/install-winusb.ps1`）：
* INF 仍以 here-string **内嵌**在脚本里（所以不需要下载任何附加文件）；
* 检测到非管理员时，用 `$env:VGP_URL` 重新拉取自己并在**提权会话**里执行
  （`Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command','irm $env:VGP_URL | iex'`；
  子进程默认继承环境变量，所以 URL 能带过去）；
* 若 `$env:VGP_URL` 为空（例如直接下载文件运行），给出提示；
* 脚本 URL 由页面按 `new URL('install-winusb.ps1', document.location.href)` 生成，
  所以放到任何 host/端口都自适应。

验证：`irm http://127.0.0.1:8899/web/install-winusb.ps1` 取回 4193 字符、
含提权逻辑 / 内嵌 INF / VGP_URL 回退 ✓（只做取回测试，未执行以免弹 UAC）。

（`web/install-winusb.bat` 与 `web/vgp-urm10-winusb.inf` 保留在目录里作为备用路径。）

---

## 24. ★ 按键布局是怎么映射的（UI Automation 抓取）

### 24.1 机制（三层）

1. **应用界面用命名槽位**：`FullControlPage.xbf` 里有 126 个名为 `locationNN` 的按钮槽位；
   而 `ButtonTransition.GetButtonId(name)` 的实现只是 **取名字后两位数字**：

   ```csharp
   string text = buttonName.Substring(buttonName.Length - 2, 2);   // "location07" -> 7
   num = Convert.ToInt32(text);
   ```

   ⇒ **键号 = XAML 槽位编号**，`GetButtonName(id)` 反向生成 `location0X` / `locationX`。

2. **图标/文字/该设备类型有哪些键** 来自 `CommonXML\layout_table_<设备类型>_<厂商>_<地区>.upd5.BIN`
   （共 198 份，SO=索尼 / NS / LA，地区 JP/NA/EU）。这些文件**是加密的**
   （高熵、无可读字符串，且 198 份文件共享同一个 32 字节头 —— 与 QS 码表那种"公共前缀"同一套路；
   包根目录的 `cmd.conf` 很可能就是密钥材料，因为 `QS_start()` 正是拿它当参数）。

3. **设备侧** 只知道"这套遥控器有哪些键号"（`02 <profile>` 返回键号清单），
   不知道图标/布局 —— 布局完全是应用的事。

### 24.2 取巧办法：用 UIA 直接读"渲染后的界面"

既然布局表加密，我们就不解密 —— 用 **UI Automation** 读官方应用**渲染出来的**界面，
一次拿到「槽位号 + 坐标 + 中文标签」三者：

```
[Button] id='location04' 335,962 196x112
  [Text] name='静音'
[Button] id='location08' 857,626 132x112        ← 方向"上"
[Button] id='location12' 857,738 132x112        ← "确认"
[Button] id='location20' … [Text] name='1'
[Button] id='power'      1791,374 112x112       ← 电源（不在滚动区内）
[Button] id='location50' … [Text] name='收藏夹'  ← 扩展键（弹出列表里，无坐标）
```

工具：`RE/tools/uia_dump.ps1`（**必须纯 ASCII**，PowerShell 5.1 读无 BOM 的 UTF-8 会按 ANSI 解析而报错）
+ `RE/tools/uia_layout.py`（解析成布局 JSON，含几何推断）。

### 24.3 几何推断（应用不给无标签键起名）

* `textNN` 元素是 `locationNN`/`locationNN+1` 这一对的**组标签**（如 `text02`="音量" ⇒ 02/03）；
  上下排列时**上面的为 +、下面的为 −** ⇒ 音量+/音量−、PROG+/PROG− ✓
* 中间 5 个无标签键按坐标判定：最上=上、最下=下、最左=左、最右=右、居中=确认 ✓

踩坑：`x` 归一化后**可能刚好为 0**，用 `if b.get("x")` 判断"有没有坐标"会把它们误判成没有坐标（Python 里 `0` 为假）。

### 24.4 产出的布局（`RE/tools/web/remote_layout.json`）

```
2=音量+  3=音量−  4=静音  5=PROG+  6=PROG−  7=输入
8=上  9=下  10=左  11=右  12=确认
13=指南  14=主页  15=返回  16=选项
20~28=1~9  29=-/--  30=0  31=确定
32~45=媒体簇（应用里是图标，无文字）
1=电源（单独，右上）
扩展键：50=收藏夹 51=跳转 52=显示 53=同步菜单 54=字幕 55=PIP 56=场景 57=剧院 58=宽
        59=小部件 60=Web 视频 61=音频 62=i-Manual 63=3D 64=文本 65=退出 66=数字 67=模拟
        70~72=HDMI1~3  74~76=视频1~3  78=电脑  79=组件 …
```

### 24.5 网页版已接入

`web/universal.html` 现在会：
1. 载入 `remote_layout.json`；
2. 机组装机/查键表拿到该 profile 的键号清单后，**按官方坐标（归一化 nx/ny/nw/nh）绝对定位渲染按键**，
   只显示该遥控器实际拥有的键（有标签就显示中文标签，没有就显示键号）；
3. 电源键单独放右上角红色；布局里没有坐标的扩展键（50~89）排在下方一行；
4. 点击任意按键 = `01 <profile> <键号> 80 00 00` 发射一次。

---

## 25. ★★★ XBF v1 反编译成功 —— 官方布局的完整来源

### 25.1 关键事实：应用是 XBF **v1**

```
View\ControlView\FullControlPage.xbf 头部: XBF\0  metadata=11278 node=63559  major=1 minor=0
```
`chausner/XbfTools`、`chausner/XbfAnalyzer` 都只支持 **v2**（README 明说 "XBF v2"）；
**`TeamGnome/XbfDecompiler`（LibXbf）与 `WalkingCat/XbfDump` 的操作码表是 v1 的** ✓

v1 操作码（两份实现一致）：
```
StartObject=1 EndObject=2 StartProperty=3 EndProperty=4 Text=5 Value=6
Namespace=7(带字符串!) EndOfAttributes=8 EndOfStream=9 LineInfo=10 LineInfoAbsolute=11
```

### 25.2 头部偏移"差 12"的原因

头部里 `StringTableOffset` 等 6 个偏移量都比真实位置**小 12**；`MetadataSize` 也一样
（11278 ↔ 实际元数据结束 11290）。节点流从 **MetadataSize+12** 开始。

### 25.3 做出来的两个工具

| 工具 | 说明 |
|---|---|
| `RE/xbftools/xbfdump_cli/` | C#/.NET10：把 LibXbf（v1 操作码 + XAML 输出）重定向编译，去掉 NuGet 依赖；`xbfdump <in.xbf> -o <out.xaml>`。**52 个 XBF 全部转换成功** |
| `RE/tools/xbf_v1_to_xaml.py` | **纯 Python v1→XAML 转换器**（自己装配对象树，完全可控）——FullControlPage 输出 4261 行；51/52 成功 |

两者都要处理的两个坑：① `Namespace` 节点**带一个字符串**，漏读就整体错位；② xmlns 声明会重复，XElement 不接受。

### 25.4 ★ 官方布局的完整机制（回答"按键布局怎么映射"）

以 `FullControlPage.xaml`（88 个 Button）为例，从 XAML 直接提取出网格布局：

| 键号 | 名字 | 网格(Row,Col) | 尺寸 | 样式（**语义就在样式名里**）| UIA 标签 |
|---|---|---|---|---|---|
| 2 | location02 | 0,- | 2×1 | `InsideUpButtonStyle` | （音量，配对见 3） |
| 3 | location03 | 2,- | 2×1 | `InsideDownButtonStyle` | 音量 |
| 4 | location04 | 4,- | 1×1 | — | 静音 |
| 5 | location05 | 0,- | 2×1 | `InsideUpButtonStyle` | （PROG，配对见 6） |
| 6 | location06 | 2,- | 2×1 | `InsideDownButtonStyle` | PROG |
| 7 | location07 | 4,1 | 1×1 | — | 输入 |
| 8/9/10/11/12 | 方向簇 | (1,3)(3,3)(2,2)(2,5)(2,3) | | — | 上/下/左/右/确认 |
| 13~16 | | | | — | 指南/主页/返回/选项 |
| 17/18/19 | | 0,0 / 0,1 / 0,2 | | **`DigitalButtonStyle`** | |
| 20~31 | | 网格 0..4 × 0..2 | | — | 1~9、-/--、0、确定 |
| 32~35 | | 0,3 / 0,4 / 0,5 / 0,6 | | **`Blue/Red/Green/YellowColorButtonStyle`** | 四色功能键 |
| 36~49 | 媒体簇 | | | — | |
| 50+ | 扩展键 | 另一容器里从 0,0 重新开始 | | — | 收藏夹/跳转/…/HDMI1~3 |

**四层机制**：
1. **键号 = XAML 的 `x:Name="locationNN"`**（`ButtonTransition.GetButtonId` 就是取名字后两位数字）；
2. **位置 = Grid.Row/Column + RowSpan/ColumnSpan**；
3. **语义 = 样式名**（`InsideUp/Down`=音量±、`Digital`=数字、`Blue/Red/Green/Yellow`=四色功能键）；
4. **可见性 = `Visibility` 绑定 `IsHasCommand`** —— 设备键表里没有的键自动隐藏（所以换码表后界面会变）；
   标签文字则由**加密布局表**给出 `StringID`，用 UIA 能读到渲染后的中文。

产出：`RE/tools/web/remote_layout2.json`（网格版布局，含样式与标签）

---

## 26. ★ 命令通道的"装载窗口"规则 —— 回答"快速连击为什么一直显示无回应"

起因：网页版快速连击时，日志里 TX 一连串发出去，界面却刷一片
`ERR 按键 ▼ 位置 9 → 键号 0x27 -> 无回应`；用户确认"实际上是有发射红外的"，
并猜"可能是读取频率不够快"。**实测证明：不是读得慢，是命令在设备那一侧就被丢了。**

### 26.1 旧代码为什么会出这个现象

旧 `cmd()` 每条命令都做四件事：
```
写 1 字节 0x00（解锁） → sleep 60ms → 写命令帧 → 轮询"收到了新帧吗"
```
点得快时多条 `cmd()` **并行**跑，USB 上的字节顺序就变成
`解锁A → 解锁B → 帧A → 帧B`（解锁字节插到别人的帧前面）。
外加旧代码用 `rxQueue.length` 当"新帧"判据、而且取的是**最后一条**回应，
就算收到回应也可能张冠李戴。

### 26.2 A/B 实测（`RE/tools/_burst_ab.py`，真机 PID_0883）

同一帧（profile 0x6FF5，键号 0x01）连发 8 次：

| 发法 | 设备生成的回应条数 |
|---|---|
| 交错发（点击间隔 45ms） | **0/8** |
| 交错发（30ms） | **0/8** |
| 交错发（20ms） | **0/8** |
| 交错发（10ms） | **0/8** |
| 极端交错（8 个解锁先发完，再发 8 个帧） | **0/8** |
| **串行发（解锁→帧→等回应，再下一条）** | **8/8** |

串行化之后的压力测试：解锁后等 60ms 连发 **30/30**；等 15ms 也是 **30/30**。
即：**响应丢失发生在设备收到命令的那一刻，跟"读得快不快"完全无关** ——
被丢掉的命令连红外都没有发出去。

### 26.3 量出来的规则（`_arm_timing.py` / `_arm_timing2.py` / `_quiet_test.py`）

**规则 1：帧必须有一个紧邻的解锁，且不能与它同时到达**

| 解锁 → 帧间隔 | 成功率（各 10 条） |
|---|---|
| 不发解锁，直接发帧 | 0/10（另有 0/4 复测） |
| 0 ms（紧挨着发） | **0/10** |
| 3 / 5 / 10 / 15 / 20 / 30 / 60 ms | **10/10** |
| 80 / 120 ms（单条命令、无其它流量时） | 4/4 |

所以 §11.3 里写的"必须 ≥50 ms"过于保守：**真实阈值在 0 与 3 ms 之间**，
网页现在用 25 ms（留 8 倍余量）。

**规则 2：两个解锁字节之间如果**没有**帧 → 整条命令被丢，且设备进入"什么都不理"的状态**

| 两个解锁的间隔 | 成功率（各 3 条） |
|---|---|
| 5 / 20 / 50 / 100 / 200 / 400 / 800 ms | **0/3** |
| 1500 / 2500 ms | 3/3 |

这条正是旧网页并行连击时 USB 上的字节形状。

**规则 3：被打坏后必须"完全静默"才恢复，越点越坏**

| 打坏后静默 | 恢复（各 3 次） |
|---|---|
| 0 ms | 0/3 |
| 200 ms | 0/3 |
| **400 ms 及以上**（600/800/1000/1200/1500/2000） | **3/3** |
| 静默期内每 150 ms 插一条命令 | **6 秒内一直不恢复** |

即：阈值在 200–400 ms 之间；**每条命令里的解锁字节都会把静默期重新顶掉**，
所以"连击之后一直无回应、停下来等一会儿又好了"完全对得上。
复位手段的对照（`_resync.py`）：控制传输初始化（0x00/0x1E/0x19）、
`WinUsb_ResetPipe`、`WinUsb_AbortPipe+FlushPipe` **都不能替代静默**，只有静默管用。

**规则 4：按键回应是"发射完之后"才给的，实测 ≈135 ms**

之前 §9/§12 里量到的 9~10 ms 是 `0x11` 读列表的延迟。
按键帧的回应要等设备把整段红外发完：实测中位 **134.5~135.1 ms**（60 条样本，最大 136.2 ms）。
所以"读得不够快"从数量级上就不成立。

### 26.4 网页端的修法（`RE/tools/web/remote.html`，VER `2026-09-24f`）

1. **命令串行化**：`withCmdLock()` 用一条 promise 链排队，任何时刻只有一条命令在飞，
   保证每个解锁字节后面紧跟自己的帧（8/8、30/30 的依据）。
2. **收回应按绝对序号**：新增 `rxCount` / `rxAt()`，命令只认"自己发出之后"到的帧的**第一条**
   （旧代码用数组长度 + 取最后一条，一 shift 就错位、还会拿错回应）。
3. **`expect` 过滤**：按键命令只接受 2 字节的 `01 xx` 回应，迟到的上一轮回应被明确丢弃并记日志。
4. **解锁等待 60 → 25 ms**（实测阈值 3 ms；按一个键的总耗时主要花在设备发射的 135 ms 上）。
5. **超时后强制静默**：任何命令超时 → `quietUntil = now + 800ms`，队列里的后续命令先等满静默
   再发，并提示"设备被交错解锁卡住了"。这样旧代码那种"越点越坏"不会再发生。
6. **连击队列上限 6**：超出直接明确告诉用户"丢掉一次"，不再伪装成"无回应"。
7. **新增「连击自检」按钮**（`burstTest()`）：一键在真机上对比
   ①旧并行做法（预期 0~2/8）与 ②新串行做法（预期 8/8），并自带 1.4 秒静默恢复。

### 26.5 离线自测台：不用真机也能验命令通道（`_harness_cmd.js`）

改网页最容易犯的错是"改完只有真机上才知道坏没坏"（本轮就踩了一次：
新写的收帧循环里写成 `const cursor = rxCount;` 又 `cursor++`，
每次收到第一条回应就抛 `TypeError: Assignment to constant variable`，
页面表现成"自动连接失败 → 设备被占用"，看着像设备问题，其实是页面自己的 bug）。

`_harness_cmd.js` 的做法：**从 `remote.html` 里把真实的 `cmd()` / `withCmdLock()` /
`startReader()` / `rxPush()` / `rxAt()` 源码抠出来**（不是抄一份），
在 Node 的 `vm` 里配一个"按 §26.3 实测规则仿真"的假设备（单缓冲装载窗口、
双解锁打坏、无解锁打坏、打坏后 400ms 静默且写入会顶掉静默期），然后断言：

| 检查项 | 结果 |
|---|---|
| 连击 8 条同时在飞，8 条都要收到回应 | ✓ 8/8（旧代码在这里是 0/8） |
| 写出的字节时间线里没有"相邻两个 arm" | ✓ 0 处 |
| arm 与 frame 数量相等（每个解锁后面都有帧） | ✓ 8 = 8 |
| 命令超时后下一条会先等 ≥700ms 静默 | ✓ 实测 887ms |
| `cmd()` 全程不抛异常 | ✓ |

**变异测试**（把 `let cursor` 改回 `const cursor` 再跑）：自测立刻报
`✗ cmd() 抛异常：Assignment to constant variable.`、
`✗ 8 条全部收到回应（实际 0/8）`、退出码 1 —— 说明这个自测台真能抓 bug，不是摆设。
`_find_const_assign.js` 是配套的静态检查（扫 `const` 变量被 `=` / `++` / `+=` 赋值）。

### 26.6 工具与坑

新增：`_burst_ab.py`（A/B + 可复用的安全 WinUSB 封装 `UsbSafe`）、
`_arm_timing.py`（延迟曲线 / 重置验证）、`_arm_timing2.py`（双解锁）、
`_resync.py`（恢复手段对照）、`_quiet_test.py`（静默阈值）、`_serial_rate.py`（串行 30 条 + 延迟）。

踩坑（都会伪装成"设备不响应"）：
* `sird_winusb.Usb` 所有传输共用一个 `self.event`：**多线程同时收发会互相 ResetEvent，
  实测直接 0xC0000005 访问违例**。并发收发必须每次传输各自新建 OVERLAPPED + 事件（见 `UsbSafe`）。
* 读超时**不要用 `CancelIo`**（会把别的线程在飞的 IRP 一起取消，缓冲区随后被释放 → 崩溃）；
  改用 WinUSB 自己的 `PIPE_TRANSFER_TIMEOUT`，让 IRP 到点自己带错完成，不留悬空操作。

---

## 27. ★ 更正：驱动只能装**有签名**的原厂包（自制 INF 在 x64 上必被拒）

### 27.1 实测现场（用户真机、cmd 里粘贴）

```
C:\Users\ASUS>powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:VGP_URL='https://…/install-winusb.ps1'; irm $env:VGP_URL | iex"
  Sony VGP-URM10  ->  WinUSB driver helper
  INF written to: C:\Users\ASUS\AppData\Local\Temp\vgp-urm10-winusb.inf
  Installing (pnputil /add-driver ... /install) ...
    无法添加驱动程序包: 第三方 INF 不包含数字签名信息。
  [WARN] pnputil exited with code -536870353
```

命令本身**没问题**（脚本确实从 GitHub Pages 拉下来并跑了，顺带证明 Pages 是通的），
卡在最后一步：`-536870353 = 0xE000024F = SPAPI_E_NO_CATALOG_FOR_OEM_INF`
—— **x64 Windows 拒绝没有数字签名（catalog）的驱动包**。

⇒ §23 里"① 复制安装命令 / 自制 INF"这条路在干净 Windows 上是**死路**，与脚本写得好不好无关。

### 27.2 能用的那条路：原厂包本来就是签名 + 绑 WinUSB

原厂包解出来的 `Disk1\x64\`（安装时自解压到 `%TEMP%\{GUID}\`）：

| 文件 | 大小 | 说明 |
|---|---|---|
| `SIRD.inf` | 3426 B | `CatalogFile=SIRD.cat`；`[Standard.NTamd64.6.3]` 把 `USB\VID_054C&PID_0883` 指到 `USB_Install` |
| `sird.cat` | 11018 B | **`Get-AuthenticodeSignature` = Valid，签发者 `Microsoft Windows Hardware Compatibility Publisher`（WHQL）** |
| `SIRD.sys` | 19968 B | 只在 06D9（老型号）那条路上用；0883 走的是 in-box WinUSB |
| `WdfCoinstaller01011.dll` / `winusbcoinstaller2.dll` | 2.7 MB | INF 的 `CopyFiles` 需要它们在场 |

关键几段（**一个字都不能改，catalog 覆盖它的哈希**）：

```
[Standard.NTamd64.6.3]
%SIRD.DeviceDesc%=USB_Install, USB\VID_054C&PID_0883
[USB_Install]
Include = winusb.inf
Needs   = WINUSB.NT
[Dev_AddReg]
HKR,,DeviceInterfaceGUIDs,0x10000,"{AC2C0F91-97D5-452D-8F89-E055C8C498A4}"
```

⇒ 在 Win8.1/10/11 上它绑的就是**系统自带的 WinUSB**，正好是 WebUSB 要的；
本机的绑定就是它（§22.2：`oem242.inf` = `SIRD.inf`）。

### 27.3 网页端定稿：驱动只留**一个按钮**

按用户要求，把所有花活删掉：

* 删掉 `irm … | iex` 一行命令、`copyCmd()`、命令展示框、自制 INF 的下载项；
  也放弃了"打包 ZIP（签名驱动 + 本地脚本）"的方案；
* 「找不到设备？」里现在**只有一个按钮**：**点击下载原厂驱动安装包（`Sony_IR_driver_EP0000311568.exe`，10.5 MB）**，
  描述只说"装完拔插一次、刷新页面再点连接"；
* 打包时不再复制 `install-winusb.ps1/.bat/vgp-urm10-winusb.inf`（它们对新用户只会帮倒忙）。

即：**官方签名 = 唯一可靠路径**；自制 INF 只有在你把签名强制关掉或用 Zadig 时才有意义。

---

## 28. ★ 实测：**安卓手机零安装**（手机 + OTG 线 = 万能遥控器）

用户实测反馈：把适配器用 USB-C OTG 线接到安卓手机，打开 GitHub Pages 上的页面，
**不需要装任何驱动就能直接调用**（§22.4 的表格里"Android 受系统 USB 权限限制"过于保守，
实际是**完全零安装**）。

### 28.1 为什么安卓不用驱动

| | Windows | 安卓 |
|---|---|---|
| 设备访问层 | 必须有一个 INF 把设备交给某个内核驱动；厂商类（0xFF）设备没有匹配项时就是"未知设备" | 内核 **usbfs**：应用（Chrome）拿到系统 USB 授权后，直接对端点收发 |
| 权限模型 | 驱动绑定 + 独占打开（WinUSB） | 系统弹窗授权（`UsbManager.requestPermission`），Chrome 通过它 claim 厂商类接口 |
| 结果 | 必须装原厂驱动包绑 WinUSB（或 Zadig） | **插上就能用，零安装** |

### 28.2 为什么必须走 https（这条因果链值得记住）

1. 手机上先用**局域网 IP**（`http://192.168.x.x:8899`）打开 → 手机自己的日志写着
   `浏览器支持 WebUSB：否　安全上下文：否` → 页面能看，但 `navigator.usb` 是 undefined；
2. 换成 **GitHub Pages 的 https 地址** → 安全上下文成立 → `navigator.usb` 有了；
3. 安卓又不需要驱动 → **一步到位**。

也就是说：**https 是关键，驱动不是**（在安卓上）。Windows 上两者都要。

### 28.3 手机端的配套改动（网页 VER `2026-09-24k`）

窄屏（`max-width:820px`）专用 CSS：
* 遥控器面板 `order:-1` 提到最前，不用先滚过"搜索/装机/命令"三块；
* `.clusters` 横向滚动 + `.canvas { min-width:660px }` ——
  否则 1568×700 的画布被压到 380px 宽，每个键只剩 20 多像素，手指点不准；
* 「找不到设备？」里补了一句"安卓不用装驱动（实测有效）"，免得手机用户白找驱动。

### 28.4 使用条件

* OTG 线必须**支持数据**（纯充电线不行）；
* 适配器是 Full Speed、总线供电（约 100mA），不需要外接电源；
* 页面独占设备：手机上开着页面时，PC 那边就抢不到（反之亦然）。



