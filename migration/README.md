# P2.1 数据库迁移前置专项（离线）

运行中的 P1.2 本机服务仍使用原 JSON 存储；本专项不改变 UI、授权规则或数据格式，不接入校园网客户端。`staging.sql` 是独立迁移暂存结构，不是上游 OpenLicensd 的生产数据库结构。实际在 SQLite 3.46.1 验证；没有 PostgreSQL 服务或 Go 驱动，因此 PostgreSQL 语法兼容性、导入及服务器切换未验收。

## 可选的离线演练

1. 正常退出本地服务（Ctrl+C），确保没有其他实例访问数据目录。先另行备份原 `data/state.json`。如果没有生成过任何卡密或设置，可能还没有数据文件。
2. 安装或使用已有 Python 3.10+（只运行正常软件不需要 Python）。在新包目录执行：

```
python migration/rehearse.py data/state.json staging.db
```

必须指定新的数据库路径；已有文件不会被覆盖。工具拒绝运行中数据目录、未知字段、重复 ID/哈希、非法订单、非法时间和有效期、孤立审计记录等。原始时间字符串（含纳秒）按原值保存。迁移成功后核验数据库完整性、外键以及所有行与来源一致性；不会修改原 JSON。数据库和摘要含授权业务信息，只留本机，不分享。暂存库不可用于直接运行授权服务，也没有自动恢复或切换功能。

## 后续生产适配约束

优先使用上传的 OpenLicensd `server/internal/store/migrations/` 与既有服务，而不是将本暂存表直接作为生产表。上游实际模型包括 products/policies/licenses/license_machines/audit_events。P1.2 短 ID 与上游 UUID 不同；须建立确定映射、保留 legacy ID，按原计划映射 duration_days（0 -> NULL）、expiration_basis=on_first_validation、activated_at/expires_at、max_activations=1、revoked 和历史绑定状态。上游审计模型需要 actor/auth_method 等信息，历史记录不可虚构身份，保留独立来源历史。客服和人工订单须有明确映射，不能丢弃；对未激活卡须保留原期限，避免后续修改共享策略改变其权益。上游生产路径、原始卡密兼容、并发事务、授权安全及真实 PostgreSQL 测试均待完成。未确认的设备标识不能当作真实硬件身份。

## 实际验证

```
(cd migration && python -m unittest -v test_rehearse)
python migration/runtime_rehearsal.py bin/chezhi-license-linux-amd64
```

13 项迁移回归、真实本机 HTTP 生成数据迁移演练通过（2 张卡、5 条审计）。源文件未改，暂存库无完整测试卡密。仅为内部测试，不进行真实收款、生产部署或网络接入控制。


## P2.1.5 更新
暂存表支持可选 Actor、Target 字段，并保留旧数据。另附 restore_backup.py，用于校验本地业务备份 ZIP 并恢复至全新目录（目标必须不存在）。不恢复成员凭据，不覆盖原数据，不代表生产数据库迁移。详见根 README。
