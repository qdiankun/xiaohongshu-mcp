package xiaohongshu

import (
	"context"
	"time"

	"github.com/go-rod/rod"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/xpzouying/xiaohongshu-mcp/humanize"
)

const (
	urlOfCreatorHome = `https://creator.xiaohongshu.com/?source=official`

	creatorSessionCookie = "galaxy_creator_session_id"
	// creatorSessionTimeout 等待创作者中心下发会话的窗口。
	// 云机房网络和 SSO 跳转较慢，15s 容易误判，放宽到 30s。
	creatorSessionTimeout = 30 * time.Second
)

// warmUpCreatorSession 打开创作者中心并等待会话 cookie，供登录后预热使用。
// 新版创作者中心不一定再下发 galaxy_creator_session_id，因此发布流程不再用它做硬性判断。
func warmUpCreatorSession(page *rod.Page) error {
	if hasCreatorSession(page) {
		return nil
	}

	if err := page.Navigate(urlOfCreatorHome); err != nil {
		return errors.Wrap(err, "打开创作者中心失败")
	}

	deadline := time.Now().Add(creatorSessionTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if hasCreatorSession(page) {
			humanize.Delay(page.GetContext(), humanize.AfterNavigate)
			return nil
		}
	}
	logCreatorPage(page)
	return errors.New("创作者中心登录失效，请重新扫码登录")
}

// WarmUpCreatorSession 登录成功后立刻在当前浏览器里建立创作者中心会话。
// 扫码只建立主站登录态，创作者的 galaxy_creator_session_id 需要访问后才下发；
// 提前拿到并随 cookies 一起保存，后续发布就不用再赌一次自动登录。
func (a *LoginAction) WarmUpCreatorSession(ctx context.Context) error {
	return warmUpCreatorSession(a.page.Context(ctx))
}

// logCreatorPage 会话建立失败时记录当前页面，便于区分登录页、验证页或网络异常。
func logCreatorPage(page *rod.Page) {
	info, err := page.Info()
	if err != nil {
		return
	}
	logrus.Warnf("创作者中心会话未建立，当前页面: %s %s", info.Title, info.URL)
}

func hasCreatorSession(page *rod.Page) bool {
	cks, err := page.Browser().GetCookies()
	if err != nil {
		return false
	}
	for _, c := range cks {
		if c.Name == creatorSessionCookie {
			return true
		}
	}
	return false
}
