--
-- 2023-11-28
-- waf 在init阶段加载进 nginx worker

require 'waf_config'
require 'waf_util'

local rulematch = ngx.re.find --nginx 正则
local unescape = ngx.unescape_uri --uri编码解码

--[[
--是否关闭应用防火墙
 ]]
function waf_status_disable()
    if waf_config_waf_enable == "off" then
        return true
    end 
    return false
end
--[[
--域名白名单, 这些域名放行 ==匹配
]]
function waf_white_host_check()
    if waf_config_white_host_check == "on" then 
        local HOST_WHITE_RULE = waf_get_rule('whitehost.rule')
        local NGX_HOST = ngx.var.host 
        if HOST_WHITE_RULE ~= nil then 
            for _, rule in pairs(HOST_WHITE_RULE) do 
                if rule == NGX_HOST then 
                    return true 
                end 
            end 
        end 
    end 
    return false 
end 
--[[
-- IP白名单 ==匹配
 ]]
function waf_white_ip_check()
    if waf_config_white_ip_check == "on" then
        local IP_WHITE_RULE = waf_get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~=nil then
            for _, rule in pairs(IP_WHITE_RULE) do
                if rule == WHITE_IP then
                    return true
                end
            end
        end
    end
    return false
end
--[[
-- 拦截黑名单 
 ]]
function waf_black_ip_check()
    if waf_config_black_ip_check == "on" then
        local IP_BLACK_RULE = waf_get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~=nil then
            for _, rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"isjo") then
                    waf_log_record('BlackList_IP',ngx.var.request_uri,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end
--[[
-- 拦截黑名单头信息
 ]]
function waf_user_agent_attack_check()
    if waf_config_user_agent_check == "on" then
        local USER_AGENT_RULES = waf_get_rule('useragent.rule')
        local USER_AGENT = get_user_agent()
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"isjo") then
                    waf_log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end
--[[
--拦截黑名单cookie
 ]]
function waf_cookie_attack_check ()
    if waf_config_cookie_check == "on" then
        local COOKIE_RULES = waf_get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
           for _,rule in pairs(COOKIE_RULES) do
               if rule ~="" and rulematch(USER_COOKIE,rule,"isjo") then
                   waf_log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                   waf_output()
                   return true
               end
           end
        end
    end
    return false
end
--[[
--放过白名单中的url
 ]]
function waf_white_url_check()
    if waf_config_white_url_check == "on" then
        local URL_WHITE_RULES = waf_get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and REQ_URI==rule then
                    return true
                end
            end
        end
    end
    return false
end
--[[
--拦截黑名单URL
 ]]
function waf_black_url_check()
    if waf_config_black_url_check == "on" then
        local URL_BLACK_RULES = waf_get_rule('blackurl.rule')
        local REQ_URI = ngx.var.uri
        if URL_BLACK_RULES ~= nil then
            for _,rule in pairs(URL_BLACK_RULES) do
                if rule ~= "" and REQ_URI==rule then
                    waf_log_record('Deny_URL',REQ_URI,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end
--[[
--url路径检查
 ]]
function waf_url_attack_check()
    if waf_config_url_check == "on" then
        local URL_RULES = waf_get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(unescape(REQ_URI),rule,"isjo") then
                waf_log_record('Deny_URL',REQ_URI,"-",rule)
                waf_output()
                return true
            end
        end
    end
    return false
end
--[[
--url参数检查
 ]]
function waf_url_args_attack_check()
    if waf_config_url_args_check == "on" then
        local ARGS_RULES = waf_get_rule('args.rule')
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            if REQ_ARGS ~= nil then
                for _, val in pairs(REQ_ARGS) do
                    if type(val) == "table" then
                        ARGS_DATA = table.concat(val, " ")
                    else
                        ARGS_DATA = val
                    end
                    if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" then
                         if rulematch(unescape(ARGS_DATA),rule,"isjo") then
                             waf_log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule)
                             waf_output()
                             return true
                         end
                    end
                end
            end
        end
    end
    return false
end
--[[
--过滤POST参数
 ]]
function waf_post_attack_check()
    local method=ngx.req.get_method()
    if waf_config_post_check == "on" and method == "POST" then
        local boundary = get_boundary()
        if boundary then
            --这是文件上传
            local POST_ARGS =ngx.req.get_body_data()
            local FILE_RULES = waf_get_rule('file.rule')
            if rulematch(POST_ARGS,FILE_RULES,"isjo") then
                waf_output()
                return true
            end
        else
            --这是表单提交
            local POST_RULES = waf_get_rule('post.rule')
            if POST_RULES ~= nil then
                for _,rule in pairs(POST_RULES) do
                    local POST_ARGS =ngx.req.get_body_data()
                    if POST_ARGS ~=nil then
                        if rulematch(unescape(POST_ARGS),rule,"isjo") then
                            waf_output()
                            return true
                        end
                    end
                end
            end
        end

    end
    return false
end

