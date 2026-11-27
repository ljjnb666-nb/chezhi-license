package main

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var beijing = time.FixedZone("UTC+8", 8*60*60)

func when(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.In(beijing).Format("2006-01-02 15:04:05")
}
func localTime(t time.Time) string { return when(&t) }
func money(cents int64) string     { return fmt.Sprintf("%d.%02d", cents/100, cents%100) }
func channelName(c string) string {
	switch c {
	case "test":
		return "内部测试"
	case "wechat":
		return "微信"
	case "alipay":
		return "支付宝"
	}
	return "其他"
}

type Stats struct {
	Total, Active, Unused, Expired, Revoked, Unbound, Orders int
	ManualCents                                              int64
}
type Dashboard struct {
	Stats                                                 Stats
	Cards                                                 []Card
	Audits                                                []Audit
	QQ                                                    string
	Q, Status, Channel                                    string
	Count, Page, Pages, AuditCount, AuditPage, AuditPages int
	Prev, Next, AuditPrev, AuditNext                      string
}

func pageNum(s string, n int) (int, int) {
	pages := (n + 19) / 20
	if pages < 1 {
		pages = 1
	}
	p, e := strconv.Atoi(s)
	if e != nil || p < 1 {
		p = 1
	}
	if p > pages {
		p = pages
	}
	return p, pages
}
func dashboardFilters(qq string, q url.Values) Dashboard {
	d := Dashboard{QQ: qq, Q: strings.TrimSpace(q.Get("q")), Status: q.Get("status"), Channel: q.Get("channel")}
	if len(d.Q) > 80 {
		d.Q = ""
	}
	switch d.Status {
	case "未激活", "已激活", "已解绑", "已过期", "已吊销":
	default:
		d.Status = ""
	}
	switch d.Channel {
	case "test", "wechat", "alipay":
	default:
		d.Channel = ""
	}
	return d
}

func buildDashboard(s State, now time.Time, q url.Values) Dashboard {
	d := dashboardFilters(s.QQ, q)
	orders := map[string]bool{}
	var filtered []Card
	for i := len(s.Cards) - 1; i >= 0; i-- {
		c := s.Cards[i]
		d.Stats.Total++
		st := cardStatus(c, now)
		switch st {
		case "未激活":
			d.Stats.Unused++
		case "已激活":
			d.Stats.Active++
		case "已解绑":
			d.Stats.Unbound++
		case "已过期":
			d.Stats.Expired++
		case "已吊销":
			d.Stats.Revoked++
		}
		if c.Channel != "test" {
			orders[c.SaleRef] = true
			d.Stats.ManualCents += int64(c.AmountCents)
		}
		if d.Status != "" && st != d.Status || d.Channel != "" && c.Channel != d.Channel {
			continue
		}
		if d.Q != "" && !strings.Contains(strings.ToLower(c.Prefix), strings.ToLower(d.Q)) && !strings.Contains(strings.ToLower(c.SaleRef), strings.ToLower(d.Q)) {
			continue
		}
		filtered = append(filtered, c)
	}
	d.Stats.Orders = len(orders)
	d.Count = len(filtered)
	d.Page, d.Pages = pageNum(q.Get("page"), d.Count)
	start := (d.Page - 1) * 20
	end := min(start+20, len(filtered))
	d.Cards = filtered[start:end]
	d.AuditCount = len(s.Audit)
	d.AuditPage, d.AuditPages = pageNum(q.Get("ap"), d.AuditCount)
	for i := d.AuditCount - 1 - (d.AuditPage-1)*20; i >= 0 && len(d.Audits) < 20; i-- {
		d.Audits = append(d.Audits, s.Audit[i])
	}
	d.addLinks()
	return d
}

func (d *Dashboard) addLinks() {
	link := func(p, ap int) string {
		v := url.Values{"view": {"cards"}, "q": {d.Q}, "status": {d.Status}, "channel": {d.Channel}, "page": {strconv.Itoa(p)}, "ap": {strconv.Itoa(ap)}}
		return "/?" + v.Encode()
	}
	if d.Page > 1 {
		d.Prev = link(d.Page-1, d.AuditPage)
	}
	if d.Page < d.Pages {
		d.Next = link(d.Page+1, d.AuditPage)
	}
	if d.AuditPage > 1 {
		d.AuditPrev = "/?view=audit&ap=" + strconv.Itoa(d.AuditPage-1)
	}
	if d.AuditPage < d.AuditPages {
		d.AuditNext = "/?view=audit&ap=" + strconv.Itoa(d.AuditPage+1)
	}
}

// Explicit section navigation, with backwards-compatible legacy filter URLs.
func adminSection(q url.Values) string {
	switch q.Get("view") {
	case "overview", "issue", "cards", "audit", "settings", "orders", "devices", "plans", "account", "members", "backup":
		return q.Get("view")
	}
	if q.Has("q") || q.Has("status") || q.Has("channel") || q.Has("page") {
		return "cards"
	}
	if q.Has("ap") {
		return "audit"
	}
	return "overview"
}
func auditLabel(action string) string {
	switch action {
	case "login_success":
		return "登录成功"
	case "login_failed":
		return "登录失败"
	case "logout":
		return "退出登录"
	case "logout_all":
		return "退出全部会话"
	case "password_changed":
		return "更新管理员密码"
	case "password_failed":
		return "密码验证失败"
	case "issue":
		return "生成卡密"
	case "bind":
		return "绑定设备"
	case "unbind":
		return "解除绑定"
	case "revoke":
		return "吊销授权"
	case "support_config":
		return "更新客服设置"
	case "plans_config":
		return "更新套餐"
	case "member-create":
		return "添加成员"
	case "member-reset":
		return "重置成员凭据"
	case "member-role":
		return "调整成员角色"
	case "member-disable":
		return "停用成员"
	case "member-enable":
		return "启用成员"
	}
	return "其他操作"
}
func adminError(err error) string {
	if strings.HasSuffix(err.Error(), "：请输入有效价格") {
		return err.Error()
	}
	var num *strconv.NumError
	if errors.As(err, &num) {
		return "请输入有效的数字。"
	}
	switch err.Error() {
	case errCommitUnknown.Error():
		return "保存结果待核验。请先按原订单号查找记录，再决定是否重试。"
	case "请检查套餐配置":
		return err.Error()
	case "invalid plan, count or amount":
		return "请检查有效期、生成数量及金额。"
	case "invalid yuan amount":
		return "请输入有效的金额（最多两位小数）。"
	case "invalid payment channel":
		return "请选择有效的付款方式。"
	case "sale reference required (max 80 bytes)":
		return "请输入订单编号，或缩短过长的编号。"
	case "sale reference already issued":
		return "该订单已生成卡密，请前往卡密管理查看。"
	case "confirm receipt / test before issuing":
		return "请先确认订单信息。"
	case "key collision; retry":
		return "生成失败，请重试。"
	case "QQ must be 5–12 digits", "QQ must be numeric":
		return "请输入 5–12 位数字 QQ 号码。"
	case "请确认批量操作", "请选择 1–100 张卡密及有效操作", "无效或重复的卡密 ID", "已吊销卡密不能再次操作", "所选卡密存在未绑定设备", "部分卡密不存在，未执行任何操作":
		return err.Error()
	default:
		return "操作未完成，请重试或联系管理员。"
	}
}

// Decimal yuan -> integer cents, never using floating-point arithmetic.
// Keep the previous cents field for existing local automation.
func parseIssueAmount(f url.Values) (int, error) {
	if !f.Has("amount_yuan") {
		return strconv.Atoi(f.Get("amount"))
	}
	invalid := errors.New("invalid yuan amount")
	if f.Has("amount") || len(f["amount_yuan"]) != 1 {
		return 0, invalid
	}
	raw := strings.TrimSpace(f.Get("amount_yuan"))
	parts := strings.Split(raw, ".")
	digits := func(s string) bool {
		if s == "" {
			return false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	if len(parts) > 2 || !digits(parts[0]) || len(parts[0]) > 7 {
		return 0, invalid
	}
	whole, e := strconv.Atoi(parts[0])
	if e != nil || whole > 1000000 {
		return 0, invalid
	}
	cents := 0
	if len(parts) == 2 {
		if len(parts[1]) > 2 || !digits(parts[1]) {
			return 0, invalid
		}
		cents, _ = strconv.Atoi(parts[1])
		if len(parts[1]) == 1 {
			cents *= 10
		}
	}
	total := whole*100 + cents
	if total > 100000000 {
		return 0, invalid
	}
	return total, nil
}
