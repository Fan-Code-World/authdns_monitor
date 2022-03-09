#!/usr/bin/env python
# coding=utf-8
import json
import requests
import time
import datetime
import subprocess, sys
from format_nameserver import Find_alldns_nameservers


class Dns_monitoring:
    def loger(self, log_win, s_code = 200):
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        content = now + ', ' + log_win
        print (content)
        if s_code !=  200:
            f = open('error.log', 'a')
        else:
            f = open('result.log', 'a')
        f.write(content + '\n')
        f.close()

    def dig_too(self, ipaddr, domain ):
        list_dns = subprocess.getoutput('dig @%s %s A +short  +timeout=30 +tries=3 '%(ipaddr,domain))
        return (list_dns.replace('\n', ';') )

    def sendCmd(self, url, params):
        headers = {'Content-Type': 'application/json'}
        r = requests.post(url, data=json.dumps(params), headers=headers, )    
        return (eval(r.text))

    def post_wx_work(self, Webhook_url, content):   
        url = Webhook_url
        params = {"msgtype": "text",
                  "text": {
                      "content": "%s"%(content.replace("  ","")) 
                      }
                 }
        return (self.sendCmd(url, params ))

    def All_test(self, All_domain_nameservers_ip):

        #
        for domain in All_domain_nameservers_ip:
            timeout_server_ip = []
            timeout_server_name = []

            error_server_ip = []
            error_server_name = []
            #
            for nameserver_name in All_domain_nameservers_ip[domain]['nameserver']:
                for nameserver_ip in All_domain_nameservers_ip[domain]['nameserver'][nameserver_name]:
                    respones = self.dig_too(nameserver_ip, domain)

                    #Authoritative DNS response result : 'timed out'
                    if "timed out" in respones:
                        timeout_server_ip.append(nameserver_ip)
                        timeout_server_name.append(nameserver_name)
                        self.loger("domain:%s, nameserver-name:%s, nameserver-ip:%s, respones:'null', Parse timeout! "%(
                            domain,nameserver_name,nameserver_ip),s_code=300)

                    #Authoritative DNS response result : rcode=refuse or servfail or nxdomain
                    elif "." not in respones:
                        error_server_ip.append(nameserver_ip)
                        error_server_name.append(nameserver_name)
                        self.loger("domain:%s, nameserver-name:%s, nameserver-ip:%s, respones:'null', Parse error!!! "%(
                            domain,nameserver_name,nameserver_ip),s_code=360)

                    else :  
                        self.loger("domain:%s, nameserver-name:%s, nameserver-ip:%s, respones:%s, Parsing succeeded"%(
                            domain,nameserver_name,nameserver_ip,respones),s_code=200) 

            all_ip_sum = All_domain_nameservers_ip[domain]['status']['nameserver_ip_sum']

            timeout_error_sum = len(timeout_server_ip) + len(error_server_ip)
            if timeout_error_sum  >= all_ip_sum / 2  :
                self.log_and_post(
                       "一半及以上的权威DNS应答存在问题!!! \n \
                        校验的域名名称 : %s, \n \
                        权威服务器信息统计 : %s,\n \
                        所有的权威服务器名称 : %s,  \n \
                        问题权威DNS服务器比例 : %s:%s !!!,\n \
                        超时的权威DNS服务器名称 : %s, \n \
                        超时的权威DNS服务器IP地址 : %s, \n \
                        错误的权威DNS服务器名称 : %s, \n \
                        错误的权威DNS服务器IP地址 : %s, \n \
                        Please check for errors !!! "%(
                             domain,
                             All_domain_nameservers_ip[domain]['status'],
                             list(All_domain_nameservers_ip[domain]['nameserver'].keys()),
                             timeout_error_sum,All_domain_nameservers_ip[domain]['status']['nameserver_ip_sum'],
                             timeout_server_name,
                             timeout_server_ip,
                             error_server_name,
                             error_server_ip,
                             ),s_code=400)

    def log_and_post(self, content, s_code ):
        self.loger(content,s_code)
        return_code = t1.post_wx_work(
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=1207b345-7471-466f-b47b-54e36f568ff7", 
             content)
        
        if return_code['errcode']==0:
            self.loger("Alert message has been sent successfully, status_code:%s"%(return_code),s_code=422)
        else:
            self.loger("Failed to send alarm information, status_code:%s"%(return_code),s_code=422)

if __name__ == '__main__':
    t1 = Dns_monitoring()
    t1.loger("The dial test tool starts running") 

    Find_any = Find_alldns_nameservers()
    All_domain_nameservers_ip = Find_any.all_dns_name("monitor_domain_list")
    t1.loger("Data initialization is complete, start to run the dial test tool. data:%s"%(All_domain_nameservers_ip)) 
    
    a = 1
    while a == 1:
        t1.All_test(All_domain_nameservers_ip)
        time.sleep(45)

    print ('code is %s' %(return_code))
