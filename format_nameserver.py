#!/usr/bin/env python
# coding=utf-8
import json
import requests
import subprocess, sys
import time, datetime

class Find_alldns_nameservers:
    def all_dns_name(self,domain_list):
        domain_dic = {}
        file = open(domain_list, 'r');
        for domain_name in file.readlines():
            domain_name = domain_name.strip('\n')
            #print (domain_name)
            root_response_list = self.tld_authdns_find(domain_name)
            iterator_dns_response = self.secondary_authdns_find(domain_name,root_response_list)
            auth_dns = self.purify_ns_gule(domain_name, iterator_dns_response)
            domain_dic[domain_name] = {}
            domain_dic[domain_name]['status']={}

            for domain_and_ip in auth_dns:
                namedserver_name  = domain_and_ip.split()[0]
                
                if "nameserver" not in domain_dic[domain_name].keys():
                    domain_dic[domain_name]['nameserver']={}

                if namedserver_name not in domain_dic[domain_name]['nameserver']:
                    domain_dic[domain_name]['nameserver'][namedserver_name]=[]
                domain_dic[domain_name]['nameserver'][namedserver_name].append(domain_and_ip.split()[1])

            #print (domain_dic[domain_name])
            domain_dic[domain_name]['status']['nameserver-name_sum'] = len(domain_dic[domain_name]['nameserver'])
            sum = 0
            for i in domain_dic[domain_name]['nameserver'].values():
                sum = sum + len(i)

            domain_dic[domain_name]['status']['nameserver_ip_sum'] = sum

        return (domain_dic)

    def tld_authdns_find(self,domain):
        root_response_list = []
        root_response = subprocess.getoutput('dig @199.7.83.42 +nocmd %s NS +noall +answer +additional +timeout=1 +tries=1 |grep -w "A" '%(domain))

        for i in root_response.split("\n") :
            try:
                tld_name_ip = i.split()[0]+" "+i.split()[-1]
            except :
                print (i)
                continue
            root_response_list.append(tld_name_ip)
        return (root_response_list)

    #整理上级权威应答的包
    def format_nameserver(self, respones_list):
        tld_respones_list = []

        #遍历获得的二级域NS and gule，将二级域nameserver and  nameserver-ip放置到列表中返回
        for i in respones_list.split("\n"):
            secondary_dns_ip = i.split()[0]+" "+i.split()[-1]
            tld_respones_list.append(secondary_dns_ip)
        return(tld_respones_list)


    #校验是否还存在NS授权记录
    def Whether_to_return_NS_record(self, domain, tld_response_list):
        for nameserver_and_ip in tld_response_list:
            check_response = subprocess.getoutput(
                'dig @%s +nocmd %s  +noall +answer  +timeout=1 +tries=1'%(
                     nameserver_and_ip.split()[1], domain))
            if "." in check_response:
                break
    
            check_response = subprocess.getoutput(
                'dig @%s +nocmd %s NS +noall +answer +authority +timeout=1 +tries=1'%(
                     nameserver_and_ip.split()[1], domain))
            if "NS" in check_response:
                #return(slef.format_nameserver(check_response))
                return('is_ns')
            elif "timed out" in (check_response):
                continue
                    
        return('no_ns')

    #向收到的NS及gule发起请求，接受子权威NS及gule
    def secondary_authdns_find(self, domain, root_response_list):

        #向目标权威遍历DNS发起请求，直到返回对应的授权NS and gule 信息
        for tld_name_ip in root_response_list:
            tld_response = subprocess.getoutput(
                'dig @%s +nocmd %s NS +noall +answer +additional +timeout=1 +tries=1|grep -w "A" '%(
                    tld_name_ip.split()[1], domain))

            if "timed out" in tld_response :
                print ("timout is %s"%(tld_name_ip.split()[1]))
                continue
            
            #is null 
            elif '.' not in tld_response :
                print ("nameserver:%s respones null,'.' not in tld_response :%s"%(
                    tld_name_ip.split()[1], tld_response))
                print (domain, root_response_list,tld_response)
                continue
            else :
                break

        return (tld_response)

    def purify_ns_gule(self, domain_name, iterator_dns_response):
        format_dns_response = self.format_nameserver(iterator_dns_response)
        exists_ns = self.Whether_to_return_NS_record(domain_name,format_dns_response)

        #is_ns , 那么在进行一次迭代,拿到最终的NS
        if 'is_ns' in exists_ns :
            iterator_dns_response = self.secondary_authdns_find(domain_name, format_dns_response)
        
        tld_response_list =  self.format_nameserver(iterator_dns_response)
        return(tld_response_list)


if __name__ == '__main__':
    t1 = Find_alldns_nameservers()
    print ("The dial test tool starts running")
    data = t1.all_dns_name("monitor_domain_list")
    print ("Data initialization is complete, start to run the dial test tool. data:%s"%(data))
