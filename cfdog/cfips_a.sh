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

# 可以增加一个参数，只在 被CC状态下才上报ip，其他时间不上报。
if [[ $cfAttack != 1 ]];then 
    exit ;
fi 
###

#开始检测 
for host in $hosts
do 
    # 如果 web.ff.xyz.cc.ip 文件不存在或为空，说明，没攻击ip，跳过
    if [[ ! -s ${logPath}${host}.cc.ip ]];then 
        continue
    fi 
    #
    # 处理ip文件表
    sort ${logPath}${host}.cc.ip | uniq > ${logPath}${host}.cc.ip.bak
    echo > ${logPath}${host}.cc.ip  #清空这个列表
    ips=`cat ${logPath}${host}.cc.ip.bak`
    #
    # 先将 ips 写入到 ip黑名单，reload  nginx，先防护
    echo $ips >> ${wafConfPath}blockip
    systemctl reload nginx 
    #
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
        echo $ip >> ${logPath}${domain}.cc.ip.cf # 写入ip到 ip记录cf文件中
    done 
    #
    # 上报完毕，把黑名单里面的 ip数据清除了。
    echo > ${wafConfPath}blockip
    systemctl reload nginx 
done 

###
#  可以进一步优化的地方：
#  1. cfAttack==1 时， 将ips加入到 blockip 黑名单。 nginx reload 。 快速屏蔽ip。
#  2. cfAttack==0 时， 将ips逐个提交到 cf 挑战。 清空 blockip名单， nginx reload。 这时候，可以悠闲逐个上传ip了。
###