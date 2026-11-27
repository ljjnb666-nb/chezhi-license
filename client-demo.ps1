Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$form = New-Object Windows.Forms.Form
$form.Text = '澈知科技 · 授权验证（本机演练）'
$form.StartPosition = 'CenterScreen'
$form.ClientSize = New-Object Drawing.Size(475, 550)
$form.MinimumSize = New-Object Drawing.Size(491, 589)
$form.AutoScaleMode = 'Dpi'
$form.BackColor = [Drawing.Color]::FromArgb(245,245,247)
$form.Font = New-Object Drawing.Font('Microsoft YaHei UI', 10)
function Add-Label($text,$x,$y,$w,$h,$size=10) {
    $label=New-Object Windows.Forms.Label
    $label.Text=$text; $label.Location=New-Object Drawing.Point($x,$y); $label.Size=New-Object Drawing.Size($w,$h)
    $label.Font=New-Object Drawing.Font('Microsoft YaHei UI',$size); $form.Controls.Add($label); return $label
}
function Add-Field($x,$y,$text) {
    $box=New-Object Windows.Forms.TextBox; $box.Location=New-Object Drawing.Point($x,$y); $box.Size=New-Object Drawing.Size(407,30); $box.Text=$text; $form.Controls.Add($box); return $box
}
$null=Add-Label '软件授权验证' 34 25 407 46 23
$null=Add-Label 'CHEZHI LICENSE  /  本机测试' 34 76 407 27 10
$null=Add-Label '授权服务地址（从服务器窗口复制）' 34 122 407 25
$address=Add-Field 34 150 'http://127.0.0.1:'
$null=Add-Label '授权卡密' 34 194 407 25
$key=Add-Field 34 222 ''; $key.MaxLength=100; $key.UseSystemPasswordChar=$true
$null=Add-Label '测试设备标识（不是硬件身份）' 34 266 407 25
$device=Add-Field 34 294 'test-device-A'; $device.MaxLength=200
$button=New-Object Windows.Forms.Button; $button.Text='激活 / 验证'; $button.Location=New-Object Drawing.Point(34,346);$button.Size=New-Object Drawing.Size(407,46);$button.BackColor=[Drawing.Color]::FromArgb(0,113,227);$button.ForeColor=[Drawing.Color]::White;$button.FlatStyle='Flat';$button.FlatAppearance.BorderSize=0;$form.Controls.Add($button);$form.AcceptButton=$button
$status=Add-Label '请先启动本地授权服务。' 34 412 407 84
$null=Add-Label '仅测试软件授权，不连接真实支付或网络认证。' 34 509 407 27 9
$button.Add_Click({
    $uri=$null
    if(-not [Uri]::TryCreate($address.Text.Trim(),[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'http' -or $uri.Host -ne '127.0.0.1' -or $uri.Port -lt 1 -or $uri.AbsolutePath -ne '/' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){$status.Text='请输入服务器显示的本机 HTTP 地址。';return}
    if([string]::IsNullOrWhiteSpace($key.Text) -or [string]::IsNullOrWhiteSpace($device.Text)){$status.Text='请填写卡密和测试设备标识。';return}
    $button.Enabled=$false; $status.Text='正在验证…'; $form.Refresh(); $resp=$null; $stream=$null; $reader=$null
    try {
        $target=[Uri]::new($uri,'/api/demo/activate')
        $req=[Net.HttpWebRequest]::Create($target); $req.Method='POST';$req.ContentType='application/json';$req.Proxy=$null;$req.AllowAutoRedirect=$false;$req.Timeout=4000;$req.ReadWriteTimeout=4000
        $body=[Text.Encoding]::UTF8.GetBytes((@{key=$key.Text;device=$device.Text}|ConvertTo-Json -Compress));$req.ContentLength=$body.Length
        $stream=$req.GetRequestStream();$stream.Write($body,0,$body.Length);$stream.Close();$stream=$null
        $resp=$req.GetResponse();if([int]$resp.StatusCode -ne 200){throw 'Unexpected response'}
        $reader=New-Object IO.StreamReader($resp.GetResponseStream()); $buf=New-Object char[] 4097; $count=$reader.ReadBlock($buf,0,$buf.Length);if($count -lt 1 -or $count -gt 4096){throw 'Oversize response'}
        $result=(-join $buf[0..($count-1)])|ConvertFrom-Json
        if($result.valid -isnot [bool]){throw 'Invalid response'}
        if($result.valid -eq $true){$status.ForeColor=[Drawing.Color]::ForestGreen;$status.Text='授权验证成功。' + [Environment]::NewLine + '有效期至：' + $result.expiry;$key.Clear()}
        else {$status.ForeColor=[Drawing.Color]::Firebrick;$messages=@{device_mismatch='卡密已绑定其他测试设备。';expired='卡密已过期。';revoked='卡密已吊销。';not_found='卡密不存在。';invalid_input='输入不合法。'};$status.Text=$messages[[string]$result.reason];if(-not $status.Text){$status.Text='授权未通过。'}}
    } catch { $status.ForeColor=[Drawing.Color]::Firebrick;$status.Text='验证未完成。请检查本地服务、地址或请求频率。' }
    finally {if($reader){$reader.Dispose()};if($resp){$resp.Dispose()};if($stream){$stream.Dispose()};$button.Enabled=$true}
})
[void]$form.ShowDialog()
$form.Dispose()
