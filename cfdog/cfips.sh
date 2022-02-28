#!/bin/bash
source /etc/profile

# 配置所在地 cfdog cfConfig.sh 
cfConf="/root/cfdog/cfConfig.sh"
logPath="/www/wwwlogs/waf/"
wafConfPath="/www/server/panel/vhost/wafconf/"
# 加载配置参数和 状态
source $cfConf
## Email of your account Cloudflare 优先级高于 $cfConf
# cfEmail= 
## You're Global API Key 优先级高于 $cfConf
# cfKey= 
## 需要监控的 域名  这里的优先级 高于 $cfConf
# hosts=" 多个域名 用 空格隔开"
##  域名zoneID,域名去掉 . ,如 a.b.com， 取 abcomZoneId= 这里的优先级，高于 $cfConf
# abcomZoneId=xxxxxxxx

#开始检测 
for host in $hosts
do 
    #
    #被CC状态， ip加入 waf黑名单
    if [[ $cfAttack == 1 ]];then   # 如果 记录 ip为空，跳过
        if [[ ! -s ${logPath}${host}.cc.ip ]];then   # 如果 web.ff.xyz.cc.ip 文件不存在或为空，说明，没攻击ip，跳过
            continue
        fi 
        # ip表写入 waf blockip列表, 同时有个备份知晓这个来源
        sort ${logPath}${host}.cc.ip | uniq > ${logPath}ccips.tmp
        cat ${logPath}${host}.tmp >> ${wafConfPath}blockip
        cat ${logPath}${host}.tmp >> ${logPath}${host}.cc.ip.bak
        echo > ${logPath}${host}.cc.ip  #清空这个列表
        systemctl reload nginx 
    fi
    #
    # 非cc状态下，上报cf的ip
    if [[ $cfAttack == 0 ]];then   
        if [[ ! -s ${wafConfPath}blockip || ! -s ${logPath}${host}.cc.ip.bak ]];then  #如果waf黑名单列表为空 或 域名cc.ip.bak列表为空 就跳过。
            continue
        fi
        # 获取 被屏蔽的ip列表
        sort ${logPath}${host}.cc.ip.bak | uniq > ${logPath}${host}.cc.ip.bak   #再排序一次，防止重复
        ips=`cat ${logPath}${host}.cc.ip.bak`
        # 获取 hostname 和 zoneID
        domain=${host#*.}
        #获取 cfips
        cfips=`cat ${logPath}${domain}.cc.ip.cf`
        #获取 zoneid
        zoneDomain=${domain//.}
        zoneId=`eval echo \${zoneDomain}ZoneId `
        if [[ -z $zoneId ]];then 
            zoneId=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$domain" -H "X-Auth-Email: $cfEmail" -H "X-Auth-Key: $cfKey" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1 )
            echo ${zoneDomain}ZoneId=$zoneId >> $cfConf
        fi 
        #
        # 逐个获取ip并上报
        for ip in $ips
        do  
            if [[ $cfips =~ $ip ]];then  #检测是否在 cfips里面, 如果已经存在了，就不用上报了。
                continue
            fi 
            #开始上报ip ，默认为 自动管理 挑战模式（不是 图像挑战，也不是 5秒盾）
            curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneId/firewall/access_rules/rules" \
                -H "X-Auth-Email: $cfEmail" \
                -H "X-Auth-Key: $cfKey" \
                -H "Content-Type: application/json" \
                --data '{"mode":"managed_challenge","configuration":{"target":"ip","value":"'$ip'"},"notes":"CC Attatch"}'
            echo $ip >> ${logPath}${domain}.cc.ip.cf   # 写入ip记录到 cf列表
        done 
        #
        # 上报完毕，把黑名单里面的 ip数据清除了。
        echo > ${wafConfPath}blockip
        systemctl reload nginx 
    fi
done 

###
#  优化的地方：
#  1. cfAttack==1 时， 将ips加入到 blockip 黑名单。 nginx reload 。 快速屏蔽ip。
#  2. cfAttack==0 时， 将ips逐个提交到 cf 挑战。 清空 blockip名单， nginx reload。 这时候，可以悠闲逐个上传ip了。
###