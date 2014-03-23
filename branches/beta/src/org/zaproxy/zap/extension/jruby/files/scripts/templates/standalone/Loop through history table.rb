# This script loops through the history table - change it to do whatever you want to do :)
# 
# Standalone scripts have no template.
# They are only evaluated when you run them.
require 'java'

# TODO work out how to access Java constants from jruby
# extHist = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension(org.parosproxy.paros.extension.history.ExtensionHistory.NAME) 
extHist = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension("ExtensionHistory") 
if (extHist != nil)
  i=1
  # Loop through the history table, printing out the history id and the URL
  hr = extHist.getHistoryReference(i)
  while (hr != nil)
    url = hr.getHttpMessage().getRequestHeader().getURI().toString()
    puts('Got History record id ' + hr.getHistoryId().to_s + ' URL=' + url) 
    i += 1
    hr = extHist.getHistoryReference(i)
  end
end
