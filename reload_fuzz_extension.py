#!/usr/bin/env python
# A basic ZAP Python API example which spiders and scans a target URL

import time
from pprint import pprint
from zapv2 import ZAPv2

target = 'http://localhost'
apikey = 'ZAPROXY-PLUGIN' # Change to match the API key set in ZAP, or use None if the API key is disabled
#
# By default ZAP API client will connect to port 8080
zap = ZAPv2(apikey=apikey, proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})
# Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
# zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})


#uninstall add-on if previously there
result = zap.autoupdate.uninstall_addon("fuzz", apikey)
#give time to uninstall
time.sleep(2)

print(result == "OK")

print(zap.autoupdate.install_local_addon("/home/dennis/zaproxy-proj/zap-extensions/addOns/fuzz/build/zapAddOn/bin/fuzz-beta-12.zap", apikey))

#give time to install
time.sleep(2)
