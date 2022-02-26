#!/bin/bash
source /etc/profile

# You're Global API Key (https://dash.cloudflare.com/profile)
cfKey= 
# Email of your account Cloudflare
cfEmail= 
# 需要监控的 域名 
hosts=" 多个域名 用 空格隔开"
# 配置所在地
conf="/root/ddoscf/ddosConfig.sh"
path="/www/wwwlogs/waf/"
# 加载攻击状态 参数
source $conf
#  填写 域名相关的 zoneId参数 到 配置中间中 域名 去掉 . 
# 去掉 . 的方法是：  host=${host//./}  这个方法
# 格式如下： hostnameZoneId=  eg.    ffokxyzZoneId=xxxx 

# 可以增加一个参数，只在 被供给状态下才上报ip，其他时间不上报。
# if [[ $cfAttack != 1 ]];then 
#     exit ;
# fi 
###

#开始检测 文件是否存在
for host in $hosts
do 
    if [[ ! -s ${path}${host}.cc.ip ]];then 
        # 如果 web.ff.xyz.cc.ip 文件不存在或为空，说明，没攻击ip，跳过
        continue
    fi 
    # 处理ip文件表
    sort ${path}${host}.cc.ip | uniq > ${path}${host}.cc.ip.bak
    echo > ${path}${host}.cc.ip  #清空这个列表
    ips=`cat ${path}${host}.cc.ip.bak`
    # 获取 hostname 和 zoneID
    domain=${host#*.}
    #获取 cfips
    cfips=`cat ${path}${domain}.cc.ip.cf`
    #获取 zoneid
    zoneId=`eval echo \${domain}ZoneId `
    if [[ -z $zoneId ]];then 
        zoneId=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$domain" -H "X-Auth-Email: $cfEmail" -H "X-Auth-Key: $cfKey" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1 )
    fi 
    # 逐个获取ip并上报
    for ip in $ips
    do  
        #检测是否在 cfips里面, 如果已经存在了，就不用上报了。
        if [[ $cfips =~ $ip ]];then 
            continue
        fi 
        #开始上报ip ，默认为 自动管理 挑战模式（不是 图像挑战，也不是 5秒盾）
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneId/firewall/access_rules/rules" \
            -H "X-Auth-Email: $cfEmail" \
            -H "X-Auth-Key: $cfKey" \
            -H "Content-Type: application/json" \
            --data '{"mode":"managed_challenge","configuration":{"target":"ip","value":"'$ip'"},"notes":"CC Attatch"}'
        # 写入ip到 ip记录文件中
        echo $ip >> ${path}${domain}.cc.ip.cf 
    done 
done 