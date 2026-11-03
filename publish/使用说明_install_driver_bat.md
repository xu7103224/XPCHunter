# templates/install_driver.bat 使用说明

本地调试用的驱动安装/卸载脚本。**不随发布包分发**——发布包走
`pnputil + INF` 的标准路径，用不上这个。

适合：实验机上反复装卸驱动验证功能。

## 用法

必须管理员权限。所有命令在 `driver_pkg` 目录内或指定路径执行。

```bat
install_driver.bat install      用 sc create 注册并启动（快）
install_driver.bat cab          解压 driver.cab 后用 pnputil 安装
install_driver.bat start        启动已注册的驱动
install_driver.bat stop         停止驱动
install_driver.bat uninstall    停止并删除服务
install_driver.bat status       查看状态
```

## 两种安装方式

### install（sc create）

```bat
install_driver.bat install
```

直接注册内核服务，不产生驱动库条目。步骤：

```
[1/3] Unblock-File 解除下载锁定
[2/3] sc create XPCHDrv type= kernel binPath= <绝对路径>
       （服务已存在时先 stop + delete 再建）
[3/3] sc start XPCHDrv
```

快（1 秒内），适合反复调试。缺点是系统不追踪这个包，卸载后没有残留记录。

### cab（pnputil）

```bat
install_driver.bat cab
```

走标准驱动包路径：

```
[1/4] 停并删旧服务
[2/4] 解压 driver.cab 到 %TEMP%
[3/4] pnputil /add-driver ... /install
[4/4] sc start XPCHDrv
```

产生驱动库条目（`oemNN.inf`），系统能追踪。适合模拟真实交付场景。
没有 `driver.cab` 时自动回退到 `install` 路径。

**注意 `pnputil` 返回 3010 是成功**（`ERROR_SUCCESS_REBOOT_REQUIRED`），
脚本已把它当成功处理并继续启动服务。

## 启动失败时的提示

`install` / `start` 失败会按退出码给处置建议：

| 码 | 含义 | 脚本给出的建议 |
|---|---|---|
| 577 | 签名无法验证 | 开 testsigning 或装证书（两条命令都打印） |
| 1058 | 服务被禁用 | `sc config XPCHDrv start= demand` |
| 1053 | 服务未及时响应 | 检查 DriverEntry 是否成功返回 |

577 是最常见的——测试证书签的驱动在没开 testsigning 的机器上必然报这个。

## 卸载

```bat
install_driver.bat uninstall
```

只停服务 + 删服务，**不删驱动文件**。

如果用 `cab` 方式装的，还要删驱动库条目：

```bat
pnputil /enum-drivers                          找到 xpchunterdrv.inf 对应的 oemNN.inf
pnputil /delete-driver oemNN.inf /uninstall
```

脚本在 uninstall 结束时会提示这一点。

## 依赖的文件

脚本按固定相对路径找文件，必须放在对应位置：

```
<某目录>\
├── install_driver.bat              本脚本
├── driver.cab                      仅 cab 模式需要
├── xpch.cer                        仅失败提示里引用
└── bin\x64\XPCHunterDrv.sys        仅 install 模式需要
```

`install` 模式只找 `bin\x64\XPCHunterDrv.sys`，`cab` 模式只找 `driver.cab`。

## 和发布流程的区别

| | install_driver.bat | 发布包 |
|---|---|---|
| 安装方式 | sc create / pnputil | pnputil + INF |
| 目标场景 | 实验机调试 | 交付用户 |
| 签名要求 | testsigning 或装证书 | 微软回签 |
| 是否进发布包 | 否 | 是（driver_pkg） |

正式交付不要带这个脚本——用户应该按标准驱动包流程安装。

## 编码

文件是**纯 ASCII + CRLF**。cmd 按 ANSI 解析，中文注释会变成乱码命令，
所以脚本里全是英文注释。改的时候别加中文。