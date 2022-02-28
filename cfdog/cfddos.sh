#!/bin/bash
source /etc/profile
# $1 = 1min, $2 = 5min, $3 = 15min
loadavg=$(cat /proc/loadavg|awk '{printf "%f", $1}')
loadavg=${loadavg%.*}

# load is 10, you can modify this if you want load more than 10
maxload=3

# Configuration API Cloudflare
# You're Global API Key (https://dash.cloudflare.com/profile)
api_key= 
# Email of your account Cloudflare
email= 
# 
zone_ids=' 多个参数中间加空格'
# 配置所在地
conf="/root/ddoscf/ddosConfig.sh"
# create file attacking if doesn't exist
test -e $conf || echo cfAttack=0 >> $conf
# 加载攻击状态 参数
source $conf

#-gt 如果负载高于限制，但记录为 0就改了
if [[ $loadavg -gt $maxload && $cfAttack = 0 ]]; then
	# Active protection
	sed -i -e "/cfAttack=/d" $conf
	echo cfAttack=1 >> $conf
	for zone_id in $zone_ids
	do
		curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/settings/security_level" \
			-H "X-Auth-Email: $email" \
			-H "X-Auth-Key: $api_key" \
			-H "Content-Type: application/json" \
			--data '{"value":"under_attack"}'
	done
fi

#-lt 如果负载低于限制，但记录为 1 就改了
if [[ $loadavg -lt $maxload && $cfAttack = 1 ]]; then
	sed -i -e "/cfAttack=/d" $conf
	echo cfAttack=0 >> $conf
	for zone_id in $zone_ids
	do
		curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/settings/security_level" \
			-H "X-Auth-Email: $email" \
			-H "X-Auth-Key: $api_key" \
			-H "Content-Type: application/json" \
			--data '{"value":"high"}'
	done
fi

exit 0
