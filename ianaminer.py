import socket
import os, sys, string, time, getopt, socket, select, re, errno, copy, signal
 
def GetIP(domain):
  result = []
  try:
    query = socket.getaddrinfo(domain,None)
    for x in query:
      result.append(x[4][0])
    return result
  except:
      return False
 
 
def queryWhois(query, server='whois.ripe.net'):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  while 1:
    try:
      s.connect((server, 43))
    except socket.error, (ecode, reason):
      if ecode==errno.EINPROGRESS: 
        continue
      elif ecode==errno.EALREADY:
        continue
      else:
        raise socket.error, (ecode, reason)
    pass
    break
 
  ret = select.select ([s], [s], [], 30)
 
  if len(ret[1])== 0 and len(ret[0]) == 0:
    s.close()
    raise TimedOut, "on data"
 
  s.setblocking(1)
 
  s.send("%s\n" % query)
  page = ""
  while 1:
    data = s.recv(8196)
    if not data: break
    page = page + data
    pass
 
  s.close()
  
  if string.find(page, "IANA-BLK") != -1:
    raise 'no match'
      
  if string.find(page, "Not allocated by APNIC") != -1:
    raise 'no match'
  
  return page      

def parseWhois(data, flags):
  data = {}
  for line in data.split('\n'):
    if line.startswith('#') or len(line) == 0:
      continue


    term = line.split(':')[0]
    detail = line.split(':')[1].strip()
    print term, '-->',detail
    print line





 
f = open('list.txt', 'r')
for x in f:
  d = x.strip()
  ips = GetIP(d)
  if ips:
    
 
    for ip in ips:
      for server in ['whois.arin.net', 'whois.ripe.net', 'whois.apnic.net', 'whois.lacnic.net', 'whois.afrinic.net']:
        try:
          res = queryWhois(ip, server)
          #print '======', server
          orgname = ''
          parseWhois(res,'')
          print res

          for x in res.split('\n'):

            if x.startswith('OrgName:'):
              orgname = x.split(':')[1].strip()
          break # we only need the info once
        except:
          pass
 
      #report
      #print d, 'has ip:', ip, 'which according to', server, 'is owned by:', orgname
 
  else:
    print 'WARNING: no IP addresses found for', d