/*
This script loops through the history table - change it to do whatever you want to do :)

Standalone scripts have no template.
They are only evaluated when you run them.
*/


import org.parosproxy.paros.control.Control
import org.parosproxy.paros.extension.history.ExtensionHistory

def extHist = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class)
if (extHist != null){
  def lastHist = extHist.getLastHistoryId()
  // Loop through the history table, printing out the history id and the URL
  for (int i = 0; i <= lastHist; i++) {
    def hr = extHist.getHistoryReference(i)
    if(hr != null){
      def url = hr.getHttpMessage().getRequestHeader().getURI().toString()
      println('Got History record id ' + hr.getHistoryId().toString() + ' URL=' + url)
    }
  }
}
