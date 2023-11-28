--
-- 2023-11-28
-- enable = "on",disable = "off"

config_waf_enable = "on" --防火墙状态
config_white_host_check = "on" --是否开启域名白名单 静态网站放行
config_white_host_list = {'myhost.bitch'} --域名白名单  ==匹配
config_white_ip_check = "on" --是否开启白名单IP检查 ==匹配
config_black_ip_check = "on" --是否开启黑名单IP检查 $$正则匹配
config_white_url_check = "on" --是否开启白名单url ==匹配 uri不带searchQuery
config_black_url_check = "on" --是否开启黑名单url ==匹配 uri不带searchQuery
config_user_agent_check = "on" --是否开启头信息检查 $$正则匹配
config_url_check = "on" --是否开启url路径检查 $$正则匹配 url带searchQuery
config_url_args_check = "on" --是否开启url参数过滤检查 $$正则匹配
config_cookie_check = "on" --是否开启cookie检查 $$正则匹配
config_post_check = "off" --是否开启post检查 $$正则匹配
config_attack_log = "on" --是否记录日志
config_log_dir = "/www/wwwlogs/waf/" --日志目录 宝塔
config_rule_dir = "/www/server/panel/vhost/wafconf/" --规则目录 宝塔
config_waf_output = "html" --设置拦截后重定向类型有 redirect/html
config_waf_redirect_url = "" --config_waf_output 设置为redirect使用的重定向地址
config_output_html=[[
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Content-Language" content="zh-cn" />
<title>网站防火墙</title>
</head>
<style>
.container{margin: 0 auto; width:640px; padding-top:20px; overflow:hidden;}
.title{height:40px; line-height:40px; color:#fff; font-size:24px; overflow:hidden; background:#6bb3f6; text-align: center;}
.box{border:1px dashed #cdcece; border-top:none; font-size:14px; background:#fff; color:#555; line-height:24px; padding:20px;20px 0 20px; overflow-y:auto;background:#f3f7f9;}
span{font-weight: bold;color:#6bb3f6;font-size: 20px;}
p{margin-top:10px; margin-bottom:10px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;color: red;}
</style>
<body>
<div class="container">
  <div class="title">Bruce's Blog 应用防火墙</div>
   <div class="box">
      <span >欢迎白帽子进行授权安全测试,安全漏洞请联系站长</span>
	  <p>你的IP已被记录,请勿在未授权情况下继续</p>
    </div>
</div>
</body>
</html>
]]
--config_waf_output设置为html返回的内容