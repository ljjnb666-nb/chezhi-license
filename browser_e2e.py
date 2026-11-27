"""Browser smoke for local prototype. Requires Playwright and Chromium."""
import subprocess, tempfile, signal, sys
from pathlib import Path
from playwright.sync_api import sync_playwright
with tempfile.TemporaryDirectory() as d:
    p=subprocess.Popen([str(Path(sys.argv[1]).resolve()),d],stdout=subprocess.PIPE,text=True)
    try:
        lines=[p.stdout.readline() for _ in range(5)]
        url=lines[1].split('URL: ')[1].strip(); pw=lines[3].split('Password: ')[1].strip()
        with sync_playwright() as playwright:
            browser=playwright.chromium.launch(executable_path='/usr/bin/chromium',args=['--no-sandbox'],headless=True)
            context=browser.new_context(viewport={'width':1440,'height':900})
            page=context.new_page(); errors=[]; page.on('pageerror',lambda e:errors.append(str(e)))
            r=page.goto(url+'login',timeout=10000); assert r.status==200
            page.locator('#password').fill(pw);page.get_by_role('button',name='登录',exact=True).click();page.get_by_role('heading',name='概览',exact=True).wait_for();page.goto(url+'?view=issue')
            page.locator('#quantity').fill('2');page.locator('#amount').fill('9.90');assert page.locator('#amount-total').inner_text()=='¥19.80'
            page.locator('#sale_ref').fill('browser-test');page.locator('[name=confirmed]').check();page.get_by_role('button',name='生成卡密',exact=True).click();page.locator('#issue-result').wait_for();assert len(page.locator('#issue-result textarea').input_value().split())==2
            print('PASS browser issue form and amount preview')
            page.goto(url+'?view=orders');assert page.get_by_text('browser-test',exact=True).count()==1;page.get_by_text('查看卡密',exact=True).click();page.get_by_role('button',name='吊销',exact=True).first.click();page.locator('#confirm-dialog').wait_for();page.locator('#confirm-cancel').click();assert page.get_by_text('未激活',exact=True).count()>=2
            page.get_by_role('button',name='吊销',exact=True).first.click();page.locator('#confirm-ok').click();page.get_by_text('操作完成',exact=True).wait_for();assert page.locator('tbody .pill.已吊销').count()==1
            print('PASS browser cancellation and confirmed revocation')
            page.goto(url+'?view=overview');assert page.locator('.trend-day').count()==7;assert not errors, errors
            if len(sys.argv)>2: page.screenshot(path=sys.argv[2],full_page=True)
            page.set_viewport_size({'width':390,'height':844});assert page.evaluate('document.documentElement.scrollWidth <= innerWidth');print('PASS overview mobile horizontal layout')
            browser.close()
    finally:
        p.send_signal(signal.SIGINT);p.wait(timeout=7)
