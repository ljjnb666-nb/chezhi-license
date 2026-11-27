# P2.1.7 集中审计结论

结论：本地候选基线通过本轮自动化回归；正式冻结与浏览器/Windows 验收仍阻塞。

| 发现 | 处理 | 证据 |
|---|---|---|
| 启动仅检查 JSON 可解析 | 增加结构与业务不变量校验，拒绝重复属性 | TestStartupIntegrity |
| 重复标量表单字段被静默取首值 | 明确拒绝，批量 ids 例外 | TestDuplicateScalarFields；HTTP 批量回归 |
| 并发重复发卡需要证明 | 20 并发请求只成功一次、仅产生两卡及两条日志 | TestConcurrentDuplicateOrder |
| 系统时钟回拨可形成激活早于发卡的记录 | 拒绝首次激活写入 | TestClockRollbackBeforeActivation |
| 订单号含 NUL 与迁移校验不一致 | 发卡入口拒绝 NUL | 源码检查、启动校验 |
| ID 截断碰撞 | 发卡时同时检查完整摘要和 ID | 源码检查 |

实际命令及证据：go test -race -count=1 -json ./...（test-results.jsonl，63 条测试/子测试 PASS）；go vet ./...；node --check admin-ui.js；五个 HTTP smoke 脚本（27 条 PASS）；migration/python -m unittest -v（22 项）；runtime_rehearsal.py（通过）；CGO_ENABLED=0 go build（Linux 及 Windows x64）。浏览器报告见 browser-results-current.txt：本机访问被管理员策略拦截，非通过。

下一步：Windows Edge 全页面及客户端窗口实机验收、独立复核；并在 PostgreSQL 专项解决跨文件事务、生产认证和部署安全。不因自动化通过宣称生产安全或所有缺陷排除。
