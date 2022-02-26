# 新增
- 2022-02-26
1. 如何防止频繁的记录IP？ 在>ip值的时候，屏蔽，在 == ip限制数的时候，记录！ 这样在整个期间，就只禁用一次。
2. 另外，可以添加到 banip列表中，这样可以禁止访问。 毕竟， ipblacklist 是优先项。 可以这么做。用来屏蔽一个访问。但是好像也不必如此，个人感觉如此。 屏蔽了，就再也访问不了了。 还是加入 cloudflare的 验证比较好。 这样可以不流失用户的前提下进行更新。
1. waf如何记录 cc的ip进行限制的？
2. 然后，记录这些ip，然后设定一个 高的值。
3. 记录下ip，然后写入到一个文件。
4. 逐个 把 ip上报给 cloudflare。 

# nginx 透过cdn获取用户真实ip
在nginx配置文件中，
http段，加上：
```conf
set_real_ip_from 0.0.0.0/0;
real_ip_header X-Forwarded-For;
```

# 1 升级 whiteurl 从 uri 到 host + uri 
waf/init.lua
```lua
function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                -- if ngxmatch(ngx.var.uri,rule,"isjo") then
                if ngxmatch(ngx.var.host..ngx.var.uri,rule,"isjo") then
                    return true 
                 end
            end
        end
    end
    return false
end
```
.. 两个点是拼接字符串的意思
/home/pi/Github/ngx_lua_waf_cf/wafconf/whiteurl 文件中可以添加域名了。注意 . 号需要用 \. ，否则代表： 贪婪任意匹配

# 2 修改 lua_shared_dict 大小限制为 100M
默认是10M /home/pi/Github/ngx_lua_waf_cf/conf/luawaf.conf 10M明显不够，换大点。应对ip段的cc攻击
```lua
lua_shared_dict limit 100m;
```

# 3 把 blockip 和 whiteip 从默认的从 config.lua文件读取，变为 从 whiteip blockip 文件读取
在 init.lua 文件第 63行增加 
```lua
-- line 63 add 
wtiprules=read_rule('whiteip')
blockiprules=read_rule('blockip')
-- whiteip 
function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
    -- 两个地方都可以正常用 
    if wtiprules ~= nil then
        for _,ip in pairs(wtiprules) do
            if getClientIp()==ip then
                return true
            end
        end
    end
        return false
end
-- blockip 
function blockip()
    if next(ipBlocklist) ~= nil then
        for _,ip in pairs(ipBlocklist) do
            if getClientIp()==ip then
                ngx.exit(444)
                return true
            end
        end
    end
    if blockiprules ~= nil then
        for _,ip in pairs(blockiprules) do
            if getClientIp()==ip then
                ngx.exit(444)
                return true
            end
        end
    end
         return false
end
```

# 4 DenyCC 改造ip_uri模式，增加 ip_host模式，增加 ip_refer模式 
修改 config.lua 增加参数
```lua
CCDeny="off"
-- 参数废弃
-- CCrate="300/60"
-- 统计时间
CCseconds="300"
-- ip+uri模式的统计
uriCCrate="30"
-- ip+host模式的统计
hostCCrate="30"
-- ip+refer模式的统计
referCCrate="30"
```
修改init.lua 增加相应模式
```lua
function denycc()
    if CCDeny then
        local uri=ngx.var.uri
        -- 直接有参数了 所以不用了
        -- CCcount=tonumber(string.match(CCrate,'(.*)/'))
        -- CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local uritoken = getClientIp()..ngx.var.uri
        local hosttoken = getClientIp()..ngx.var.host
        local refertoken = getClientIp()..ngx.var.http_referer
        local limit = ngx.shared.limit
        local urireq,_=limit:get(uritoken)
        local hostreq,_=limit:get(hosttoken)
        local referreq,_=limit:get(refertoken)
        -- uri CC deny
        if urireq then
            if urireq > uriCCrate then
                 ngx.exit(444)
                return true
            else
                 limit:incr(uritoken,1)
            end
        else
            limit:set(uritoken,1,CCseconds)
        end
        -- host CC deny
        if hostreq then
            if hostreq > hostCCrate then
                 ngx.exit(444)
                return true
            else
                 limit:incr(hosttoken,1)
            end
        else
            limit:set(hosttoken,1,CCseconds)
        end
        -- refer CC deny
        if referreq then
            if referreq > referCCrate then
                 ngx.exit(444)
                return true
            else
                 limit:incr(refertoken,1)
            end
        else
            limit:set(refertoken,1,CCseconds)
        end
    end
    return false
end
```

# 增加 cc时，ip记录功能。 如果已经无法访问，再增加访问数量，就会被上报cf banip库。
init.lua 增加
```lua
function denycc()
    if CCDeny then
        local uri=ngx.var.uri
        -- 直接有参数了 所以不用了
        -- CCcount=tonumber(string.match(CCrate,'(.*)/'))
        -- CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local uritoken = getClientIp()..ngx.var.uri
        local hosttoken = getClientIp()..ngx.var.host
        local refertoken = getClientIp()..ngx.var.http_referer
        local limit = ngx.shared.limit
        local urireq,_=limit:get(uritoken)
        local hostreq,_=limit:get(hosttoken)
        local referreq,_=limit:get(refertoken)
        -- 记录 cc的 ip
        local line = getClientIp()
        local filename = logpath..'/'..ngx.var.host..".cc.ip"
        -- uri CC deny
        if urireq then
            if urireq > uriCCrate then
                 ngx.exit(444)
                return true
            -- 判断到 检测到 达到相应的值，就警报并上传到 cf
            elseif urireq == uriCCrate then
                write(filename,line)
            else
                 limit:incr(uritoken,1)
            end
        else
            limit:set(uritoken,1,CCseconds)
        end
        -- host CC deny
        if hostreq then
            if hostreq > hostCCrate then
                 ngx.exit(444)
                return true
            elseif hostreq == hostCCrate then
                write(filename,line)
            else
                 limit:incr(hosttoken,1)
            end
        else
            limit:set(hosttoken,1,CCseconds)
        end
        -- refer CC deny
        if referreq then
            if referreq > referCCrate then
                ngx.exit(444)
                return true
            elseif referreq == referCCrate then
                write(filename,line)
            else
                 limit:incr(refertoken,1)
            end
        else
            limit:set(refertoken,1,CCseconds)
        end
    end
    return false
end
```
记录ip的文件是 host.cc.ip 在 log目录下。

# 友好的攻击提示窗口？

# 网站检测攻击，进行防护功能。
ddosCf.sh 供给检测脚本功能
放入 crontab 
每分钟检测一次 
* * * * * /root/ddoscf/ddoscf.sh

# 网站攻击脚本，自动提交到 cloudflare
