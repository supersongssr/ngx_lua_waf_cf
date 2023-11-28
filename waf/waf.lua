--
-- 2023-11-28
-- 放在 nginx config server{} 内可以 实现 各个站点 设置不同的防护方案

if waf_status_disable() then --总开关 
elseif white_host_check() then --第零层 白名单域名
elseif white_ip_check() then --第一层 允许白名单过 
elseif black_ip_check() then --第二层 拦截黑名单IP 
elseif user_agent_attack_check() then --第三层 拦截黑名单user_agent 
elseif cookie_attack_check() then --第四层 拦截黑名单cookie 
elseif white_url_check() then  -- 第五层 放过白名单url 
elseif black_url_check() then  --第六层 拦截黑名单url 
elseif url_attack_check() then  --第七层 过来URL路径 
elseif url_args_attack_check() then --第八层 url参数检查 
elseif post_attack_check() then --第九层 post提交的参数检查 
else return
end
