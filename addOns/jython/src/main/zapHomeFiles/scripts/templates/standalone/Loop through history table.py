"""
This script loops through the history table - change it to do whatever you want to do :)

Standalone scripts have no template.
They are only evaluated when you run them.
""" 

from org.parosproxy.paros.control import Control
from org.parosproxy.paros.extension.history import ExtensionHistory

extHist = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME) 
if (extHist != None):
  i=1
  # Loop through the history table, printing out the history id and the URL
  hr = extHist.getHistoryReference(i)
  while (hr != None):
    url = hr.getHttpMessage().getRequestHeader().getURI().toString()
    print('Got History record id ' + str(hr.getHistoryId()) + ' URL=' + url) 
    i += 1
    hr = extHist.getHistoryReference(i)
