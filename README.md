# CheZhi License · 澈知授权管理系统

当前源码基线：**P2.1.7**。本项目是独立软件授权管理原型，仅限本机虚拟订单与授权演练，不包含校园网认证、真实收款或公网部署。

## 快速开始

需要 Go 1.23 或更高版本；推荐使用仍获安全维护的 Go 版本。克隆源码后，在 Windows PowerShell 中执行：

```powershell
New-Item -ItemType Directory -Force bin | Out-Null
go build -trimpath -o bin/chezhi-license-win-x64.exe .
.\start-windows.bat
```

打开终端提示的本机地址。首次启动使用临时管理员密码，可在账户与安全页面设置长期密码。用户激活页为 /activate，套餐页为 /purchase。停止旧实例后，备份并迁移 data 中的 state.json、plans.json、members.json、owner.json（如存在）；不要复制 instance.lock。源码仓库不包含可执行文件、运行数据或账户配置。

## 持续集成

[CI 工作流](.github/workflows/ci.yml) 覆盖 Go 回归（Linux 与 Windows）、Linux race、实际 HTTP、迁移与恢复、JavaScript 语法、Chromium 冒烟、Windows x64 构建和基础仓库敏感信息检查。PR 和 main 推送触发。构建产物仅供测试，非签名正式 Release；测试结果以对应 Actions 运行证据为准。基础敏感信息检查并非完整漏洞扫描。浏览器测试不替代 Windows Edge 实机与生产安全验收。

最新审计范围与遗留问题见 [P2.1.7 审计](AUDIT-P2.1.7.md)。当前不支持生产 PostgreSQL、跨文件原子事务、真实设备持有证明、MFA 或公网安全部署。

---

## 历史版本记录

下方保留历史记录，早期功能和验收状态不代表当前版本；冲突时以上方当前说明与最新审计为准。

# CheZhi License P2.1.5 — 操作日志与业务恢复

## 本版变更
- 发卡、解绑、吊销、客服设置在业务状态的同一次提交中记录真实登录操作者；用户绑定标记为用户操作。旧记录不推断身份。套餐和成员变更补充日志，成员操作记录目标账号（不含凭据）。两者配置与日志是不同文件，跨文件提交尚不具原子性；配置成功而日志失败时界面提示。登录失败/登录/退出、导出等尚未完整审计。
- 账户与安全新增“退出我的所有会话”，只撤销当前账户的所有 Cookie 会话；保留现有本机主管理员自动化 Basic Auth 入口。管理员请求串行执行授权与修改，避免并发角色变更与旧权限请求交错；本地原型不适用高并发生产部署。
- 新增 `migration/restore_backup.py`：验证 ZIP 文件集合、CRC（完整读取）、清单摘要、业务数据及套餐结构；只恢复到全新目录，拒绝覆盖已有目录。ZIP 不包含成员账户，不会恢复成员身份或会话。摘要不等于数字签名，只恢复信任来源的备份。
- SQLite 暂存迁移保留 Actor、Target 字段；旧版日志兼容。授权核心与客户端 API 未变。新日志字段可能不被旧迁移脚本接受；升级后使用本版工具，不要直接降级数据。

## 启动、升级与恢复
停止旧程序并备份 `data/state.json`、`data/plans.json`、`data/members.json`（如存在）。复制至新版本的 data 目录，不复制 instance.lock。双击 start-windows.bat。Windows 未签名 EXE 仅交叉编译。

主管理员下载业务备份后，在 Python 3 环境运行：

```powershell
python migration/restore_backup.py "D:\backup.zip" "D:\CheZhi-restored"
```

目标目录必须不存在。成功后可从新目录独立启动服务，例如 `bin\chezhi-license-win-x64.exe "D:\CheZhi-restored"`。先停止不再使用的旧实例，不覆盖原数据；核对授权状态、时间及订单。成员账号须另行安全保存，本工具不会导入。业务备份含敏感信息，注意文件访问权限。不要恢复来历不明的备份。

## 本版实际验收
51 个 Go 测试（含子测试），race、vet，23 组实际 HTTP 冒烟（含成员身份归属、备份恢复后启动第二实例），22 项 Python 迁移及恢复测试（13 原迁移 + 9 恢复），实际运行数据 SQLite 暂存迁移，JavaScript 语法检查，Linux x64 编译及 Windows x64 交叉编译均通过。上游授权核心、原有客户端 API、套餐模型及两个用户页面逐字节不变。日志见本包测试记录。此次未执行真实浏览器 E2E 或 Windows 实机测试；旧的浏览器限制日志仅为历史记录。

仍仅限本机虚拟订单和独立软件授权演练。尚未完成生产数据库、跨文件事务、完整安全审计、长期主管理员凭据、MFA、定时备份或生产级恢复。未接入校园网、真实支付或公网服务。以下为历史版本说明，不代表本版新增功能或本版独立验收。

---

# CheZhi License P2.1.4 — 成员权限与数据备份

## 本轮新增

- 主管理员（admin，启动时随机密码）、发卡员（查看业务与发卡）、只读成员（仅查看业务）三类角色；管理设置、解绑/吊销、成员及备份导出仅主管理员可用。服务端强制权限检查，不依赖隐藏按钮。
- 成员创建、启用/停用、角色调整、凭据重置。成员登录凭据为服务端生成的 256 位随机秘密，明文仅在创建或重置后显示；磁盘只保存 SHA-256 摘要（不接受自选弱密码）。成员记录保存在 data/members.json。成员角色变更、停用、重置后撤销其现有会话；已开始执行的请求不保证被取消。最多 100 个成员。主账号仍是启动随机密码，不支持自选密码、密码找回及 MFA。
- 数据备份页面提供业务 ZIP（state.json、plans.json、manifest.json），二者同锁快照，清单含 SHA-256；不包含完整卡密、成员记录或会话。清单用于检查误损坏，不是签名或防篡改证明。备份包含订单及授权摘要等敏感业务数据，请妥善保管。
- CSV 导出卡密前缀、套餐、订单、渠道、价格、状态和时间；不包含完整卡密、卡密哈希、设备哈希。对用户可控文本做公式前缀保护。
- 成员操作及导出尚未接入带操作者的独立审计日志。当前仍为回环地址内部原型，不用于真实销售、网络权限或公开服务。

## 升级和备份

停止旧程序（Ctrl+C），备份整个 data 目录，解压新版至独立目录，复制 state.json、plans.json（如存在）及 members.json（如存在），不要复制 instance.lock。双击 start-windows.bat，使用本次启动密码登录 admin。成员凭据不随重启改变，会话重新登录。不要覆盖其他项目。

如需恢复业务 ZIP：先停止服务，另行备份现有 data 目录；在临时目录解压，仅接受清单列出的两个 JSON 文件及 manifest.json。分别重新计算 SHA-256 与清单比对，可使用 PowerShell Get-FileHash。核对业务数据正确后手动复制两份 JSON 至新独立测试目录，再启动测试，确认卡密及套餐状态。不要覆盖原目录进行首次恢复。成员记录需单独在停机时保留 members.json；业务 ZIP 不恢复成员账号。未提供在线恢复按钮，也未完成 Windows 断电恢复测试。

## 本轮实际验收

49 项 Go 测试（含子测试）通过，race、vet、JS 语法检查通过；原有 HTTP 19 组及新增成员/备份/CSV 实际 HTTP 3 组通过；13 项 SQLite 迁移测试和实际运行数据迁移演练通过。Linux x64 与 Windows x64 交叉编译完成。7 个授权核心、存储、套餐、演练 API 与迁移文件与上一版逐字节一致。日志见 test-results.jsonl、smoke-results.txt、client-smoke-results.txt、session-smoke-results.txt、members-smoke-results.txt 和 migration/。Windows 未实机执行；本轮未运行浏览器 E2E，历史环境限制记录见 browser-results-historical.txt。Windows EXE 未签名。本轮未实现生产数据库、完整上游后台、设备密钥证明、真实支付或校园网集成。

以下为历史版本记录，不能作为本轮新验收证据。

---

# P2.1.3 套餐与管理员会话管理

- 新增独立登录页：启动窗口提供 admin 与每次启动随机密码，浏览器访问首页自动进入登录。8 小时服务端会话、HttpOnly/SameSite Strict Cookie、独立 CSRF、登录失败限流及退出失效。仅 HTTP 回环内部原型，因此未设置 Secure Cookie；禁止直接公网部署。非浏览器显式 Basic Auth 保留用于既有本地测试脚本，使用同一随机密码；错误密码也限流。退出仅撤销当前网页登录会话，不撤销脚本凭据。重启使两种凭据失效。
- 新增账户与安全页：单管理员账号、当前会话退出。不包含长期账户密码、多人账户、角色权限及密码修改。
- 新增六种固定期限套餐参考售价及公开展示开关；默认售价留空，管理员可配置。隐藏仅影响用户套餐页，不禁止管理员发卡。发卡界面随套餐预填参考价，人工可覆盖；历史订单金额及已签发卡密不变。
- 套餐数据独立保存于 data/plans.json，旧 state.json 格式不变。升级须停止程序并备份、复制两文件（没有 plans.json 则默认套餐）；不要复制 instance.lock。现有 SQLite 迁移工具只迁移 state.json，套餐文件需单独保留，未接入生产数据库。套餐变更尚无专门审计日志。
- 继续保持独立软件授权演练，不涉及真实支付或网络认证。

## 本版实际验收

45 项 Go 测试（含子测试）通过，race、vet、16 组原有 HTTP 冒烟、3 组新会话及套餐 HTTP 检查、13 项 SQLite 迁移测试、真实运行数据迁移演练、JS 语法、Linux 与 Windows x64 构建通过。Chromium 真实 E2E 再次被 ERR_BLOCKED_BY_ADMINISTRATOR 阻止，详见 browser-results.txt。Windows 未实机运行。源码核心 internal/license 未修改。完整生产数据库、持久管理员及角色、设备密钥、安全部署与正式分发仍未验收。

以下为历史版本说明，不代表本版额外通过的测试。

---

# P2.1.2 运营后台增强

本版基于 P2.1.1，保留原有 JSON 格式、授权核心、回环监听与管理员鉴权。

- 新增订单管理：按人工订单编号聚合，显示登记金额、发卡数量、曾激活和已吊销数量；支持搜索、渠道筛选及分页。不是独立支付订单或对账系统。
- 新增设备管理：显示当前保留的卡密绑定记录，支持搜索、状态筛选、分页及进入卡密管理；不暴露设备哈希，不代表物理设备清单。
- 概览新增近七日发卡趋势（按北京时间自然日统计、排除内部测试）。金额是人工登记记录。
- 发卡表单实时计算登记合计；解绑、吊销及批量操作新增确认对话框。后端原有验证不变。
- 仍是本机测试环境，不接入真实付款或网络认证。多管理员、角色权限、独立登录页、生产数据库、套餐定价管理仍待开发。

## 本版验收

42 项 Go 测试（含子测试）通过，race、vet、Linux/Windows x64 构建、16 组 HTTP 冒烟、13 项迁移测试、真实运行数据迁移演练和 JS 语法检查均通过。浏览器 E2E 已尝试运行，但 Chromium 返回 ERR_BLOCKED_BY_ADMINISTRATOR，未执行真实浏览器交互断言；详见 browser-results.txt。Windows EXE 未签名、未在 Windows 实机运行。

启动及升级仍按下文说明（先停止旧程序并备份 state.json；不要复制 instance.lock）。下文为原版历史记录。

---

# P2.1.1 授权管理工作台重构

本版基于 P2.1 数据迁移版，保留本地授权与迁移业务。五个独立后台页面使用左侧导航；发卡结果仅在人工发卡页的表单下方显示。金额表单使用元，内部仍以整数分保存；旧 amount 字段兼容。操作日志和业务错误采用中文；后台标题移除时区及开发说明，保留简短测试环境标记。数据文件格式、授权核心、限流和迁移校验规则不变。

## 更新方法

停止旧实例，备份 data/state.json，解压到新目录，复制备份到新版 data/state.json（不要复制 instance.lock），双击 start-windows.bat。访问终端给出的地址。新端口和管理员密码以本次终端输出为准。

## 本版验收

- Go Race 回归：40 个 PASS（含子测试），0 失败或跳过；go vet 与 Node JavaScript 语法检查通过。
- Linux 实际 HTTP：12 组原有管理流程、4 组原有用户/客户端流程通过；新增页面隔离、发卡结果位置、金额转换及权限回归已纳入 Go 测试。
- SQLite 迁移：13 项通过，实际运行数据迁移演练通过。
- Windows x64 交叉编译通过，SHA256SUMS.txt 已更新。浏览器 E2E 尝试返回 ERR_BLOCKED_BY_ADMINISTRATOR；未核验真实浏览器视觉、剪贴板行为或 Windows 实机运行，不能宣称这些通过。
- 仍是仅监听本机的内部测试原型，生产 PostgreSQL、远程服务、设备密钥证明、正式支付均未接入。下方为历史版本说明。

# P2.1 数据迁移前置版

基于 P1.2，保留 Apple 风格及原运行方式。本轮新增独立离线迁移工具，见 [migration/README.md](migration/README.md)。38 项 Go 测试、16 组 HTTP 冒烟、13 项迁移测试和实际运行数据迁移演练通过；生产 PostgreSQL 尚未接入。以下保留原版使用说明。

# 澈知科技 · CheZhi License P1.2 本地管理原型（Apple 风格工作台与独立授权演练）

仅限本机虚拟卡密及虚拟订单测试。不是公网授权服务，不是校园网认证客户端，不接入真实付款或网络访问权限。Windows EXE 未签名，仅交叉编译，P1.2 仍需 Windows Edge 及 WinForms 实机验收。

## 启动与升级

1. 停止 P0.1（命令行 Ctrl+C）。备份旧目录 `data/state.json`。
2. 解压本包到新的独立可写目录。如果保留旧数据，将备份的 `state.json` 复制到新目录 `data/`（如不存在则创建）。不要复制 `instance.lock`，不要覆盖 xiaoyuanwang。P1 没有改变 JSON 字段结构；旧格式读入测试通过。
3. 双击 `start-windows.bat`。终端输出本次随机端口、管理员 `admin` 与随机密码。
4. 将 URL 复制到 Edge 地址栏。首页 `/` 为管理员后台。用户激活页为 `/activate`（首页有链接），在新的 InPrivate 窗口可以不登录管理员测试用户激活。只监听 127.0.0.1，不可跨设备访问。
5. 选择快捷套餐或自定义天数、张数、虚拟订单编号、内部测试渠道，金额填 0，勾选确认后生成。请立即复制卡密；只保存哈希及前缀，不能找回原卡密。不要使用真实个人信息。
6. 用户页输入虚拟卡密及测试设备标识，验证授权和到期时间。返回管理页可筛选、解绑、吊销及批量操作。QQ 仅在后台修改，用户页自动显示。
7. Ctrl+C 退出；重启后密码和端口会变更，数据保留。异常退出残留锁文件时，先确认旧实例已停止，才可删除 `data/instance.lock`。不要删除数据。

## P1.2 新增变化

- 管理工作台紧凑导航，移除占据首屏的大段说明；保留原有发卡、筛选、分页、审计功能。
- 独立 `/purchase` 套餐说明页，动态读取客服 QQ；不展示虚构价格，不创建订单、不收款。
- 本机 JSON 演练接口 `POST /api/demo/activate`，与网页激活共用授权逻辑及限流预算；拒绝浏览器来源、非 JSON、超限与畸形请求。
- 新增 `client-demo.ps1` 与 `start-client-demo.bat`：独立 Windows PowerShell 5.1 / WinForms 演练窗口。只接受本机 127.0.0.1 的 HTTP 地址，不使用代理、不跟随重定向、不保存卡密。未执行 Windows 端实测。

### P1 / P1.1 保留变化

- 管理后台与用户激活页整体视觉重构为更接近 Apple 风格的高圆角、留白、玻璃拟态卡片与更清晰的信息层级。
- 管理员首页与普通用户测试激活页面分离：不同表单 token，管理员 Basic Auth 保留，用户仅可验证测试卡密，不读取订单、卡密列表、审计记录或管理员 token。
- 日卡/周卡/月卡/季卡/年卡/永久卡/自定义套餐，期限采用固定天数（非自然月）。
- 总量、未激活、激活、解绑、过期、吊销、人工订单数及人工记录金额统计。金额单位为人民币分录入、元显示，排除内部测试；非真实支付对账，吊销不代表退款。
- 卡密前缀及订单号搜索、状态与渠道组合筛选、每页 20 条，审计记录独立分页。不要把完整卡密填入搜索框。
- 批量解绑/吊销支持最多100条请求、界面当前页勾选。须明确确认批量操作，任一无效记录使整批不提交；吊销不可恢复，解绑不重置有效期。
- 所有界面时间以固定 UTC+8（北京时间）显示，持久化仍沿用 UTC。
- 用户激活页新增本机全局 60 次/分钟限流；不是生产级多实例限流。
- 保留 P0.1 的同源表单 Referrer-Policy、Host、Origin、CSRF、CSP 约束；非法及重复 Origin 被拒绝。

## 实际复用与边界

上游 OpenLicensd (`3170156f0e527d3e3b14b55a26a0d3ab9fc3ed50`) 的 `server/internal/license/license.go` 与 `license_test.go` 逐字节保留在 `internal/license/`，本次 cmp 对比通过。卡密生成、规范化、SHA-256、有效期计算复用既有代码。保留 LICENSE 和 NOTICE。

P1 是 P0.1 的本地适配层增量开发，不是已经完成上游全栈管理后台二开。Activation Manager 未复制源码。完整 OpenLicensd 需要 Go 1.27、外部 Go/Node 依赖及 PostgreSQL；本机环境 Go 1.23.2、未安装 PostgreSQL/Docker，未进行全栈构建。暂不为此引入第二套生产架构。

本地 JSON、单进程锁和本地 HTTP 管理员登录仅用于内部验证。用户入口只在本机可用；设备标识是可伪造字符串，未接入设备私钥持有证明；无 TLS、公网 API、生产数据库、正式客户端、真实支付、网络认证集成。Windows 数据替换和断电恢复未验证。不得把本包直接作为生产授权服务器。用户授权不代表网络接入许可。

## 实际测试及构建

Go 1.23 标准库，无联网依赖：

```
go test -race -count=1 -json ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o bin/chezhi-license-linux-amd64 .
python http_smoke.py bin/chezhi-license-linux-amd64
python client_http_smoke.py bin/chezhi-license-linux-amd64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o bin/chezhi-license-win-x64.exe .
```

实际结果：38 个测试 PASS（含子测试），0 失败、0 跳过；race 与 vet 成功；原有 Linux HTTP 冒烟 12 组、新增原型 HTTP 冒烟 4 组通过；Windows x64 交叉编译成功。尝试 Chromium 本机 E2E 时收到 ERR_BLOCKED_BY_ADMINISTRATOR，未完成浏览器测试。WinForms 脚本未在 Windows 执行；HTTP 测试不等于浏览器或原生 GUI 测试。`test-results.jsonl`、`smoke-results.txt`、`client-smoke-results.txt` 为实际输出。

源码归档来源：用户上传 OpenLicensd ZIP，文件名对应上述提交；CRC 已核验，原核心文件与归档一致，未从远端重新验证整份归档。Activation Manager 上传包保留作候选参考。正式分发前独立完成依赖、安全、许可与权利审查。

## 独立 Windows 客户端演练

1. 先启动 `start-windows.bat`，在后台生成一张内部测试卡密。
2. 双击 `start-client-demo.bat`，将服务器窗口的本机 URL 填入地址栏，填写卡密及测试设备标识。
3. 点击激活/验证，检查授权结果。可测试异机拒绝、后台解绑及吊销。窗口不连接原有校园网客户端，不控制任何其他程序。
4. 需要 Windows PowerShell 5.1 与 WinForms（通常 Windows 11 已自带）。若系统策略禁止运行脚本，先使用网页版 `/activate`，不要降低系统脚本执行策略。本包未签名。

P1.2 仍为本机原型，生产数据库和设备持有证明集成仍待开发。套餐及价格未确定；不使用真实收款。

## P2.1.6 管理后台收尾：长期密码与安全日志

本节优先于旧版本说明。升级前停止服务并备份 `state.json`、`plans.json`、`members.json`、`owner.json`（如果存在），不要复制 `instance.lock`。新安装仍由终端提供一次启动临时密码；登录后进入「账户与安全 → 登录密码」，输入当前密码及两次新密码。新密码至少 14 个字符且最多 128 UTF-8 字节，建议使用密码管理器生成唯一长密码。设置后所有主管理员会话被撤销，需重新登录；成员会话保留。服务重启后继续使用已设置的密码，终端不再显示实际密码。配置长期密码后关闭旧版 Basic Auth 兼容入口，未配置时保留内部回归兼容。密码文件只存版本、随机盐与 PBKDF2-HMAC-SHA256 摘要（600,000 轮）；不保存明文。已有成员仍使用随机生成的高熵凭据。

`owner.json` 与成员配置均不包含在网页业务备份中，需由有权限的本机管理员单独安全备份。遗忘密码时，停止程序，确认没有服务实例运行，将 `owner.json` 移到受保护的离线目录，再启动服务使用新的临时密码重新配置；不要删除业务数据。此恢复依赖操作系统文件访问权限，不是远程密码重置。损坏的账户配置拒绝启动，不会自动回退到临时密码。

操作日志新增浏览器登录成功、登录失败、退出、退出所有会话、主管理员密码变更及当前密码验证失败。失败账号统一记为 unknown，避免记录未验证身份或恶意输入；不记录密码、会话令牌。超过限流额度的请求不逐条落盘，避免日志写入放大。成功登录要求安全日志写入成功；退出即使日志写入失败也撤销会话并记录终端错误。密码文件与业务日志仍是独立文件，尚无跨文件事务。旧 Basic Auth 自动化兼容入口仅在未配置长期密码时可用，不属于浏览器登录事件审计。SQLite 演练及恢复识别新增事件。

本轮实际验证：53 个 Go 测试（含子测试）通过，race 与 vet 通过，原有 23 组 HTTP 检查及新增 4 组真实 HTTP 检查通过，22 个迁移/恢复测试通过，实际运行数据迁移通过；JS 语法检查及 Windows x64 交叉编译成功。`browser-results-current.txt` 记录本轮 Chromium 真实尝试被 `ERR_BLOCKED_BY_ADMINISTRATOR` 拒绝，不算通过；Windows GUI 和 Windows 文件替换实机未验证。MFA、生产 TLS、数据库事务、操作系统级防篡改及完整浏览器可访问性审计仍未完成，不得直接作为生产服务使用。

## P2.1.7 后台集中审计（最新）

- 启动加载 state.json 前检查 JSON 结构、重复字段（含大小写别名）、QQ、卡密摘要和 ID、订单批次一致性、激活时间及有效期、设备摘要及审计关联；发现异常拒绝启动且不修改源文件。旧版正常生成的 JSON 结构兼容。测试中的旧版虚构 hash 已改为符合真实格式的 fixture。
- 套餐、成员和主管理员配置也拒绝重复 JSON 属性。管理、登录、激活、备份等表单拒绝重复标量字段，合法批量选择仍允许多个 ids。
- 发卡拒绝含 NUL 的订单号，检测 ID 截断碰撞；首次激活时若系统时间早于发卡时间则拒绝写入。新增 20 个并发发卡请求测试，仅允许同订单成功一次。
- 本轮执行：63 个 Go 测试及子测试（race），go vet，node --check；27 组实际 HTTP 检查；22 项 Python 迁移恢复测试，运行数据 SQLite 迁移演练；Windows x64/Linux amd64 重新编译。
- Chromium E2E 实际尝试失败：ERR_BLOCKED_BY_ADMINISTRATOR，尚未打开登录页，不算浏览器测试通过。Windows GUI/Edge、剪贴板、响应式布局和视觉验收未执行。当前是本地候选基线，不是生产发布。
- 残留：独立文件之间事务原子性、生产 TLS/数据库、MFA、跨设备授权及真实硬件身份均未完成；历史日志仅为应用记录，不是防篡改审计。首次设置长期密码前仍保留本机自动化 Basic Auth 兼容路径。启动完整性检查不是对恶意本地文件修改的认证。未引入第三方组件或修改校园网认证代码。

## P2.2 PostgreSQL

The server keeps the existing loopback-only UI, client API and JSON startup
command. See [PostgreSQL setup, cutover and recovery](migration/POSTGRES.md) for
the database backend, PowerShell commands, migration, runtime grants, and backup.
