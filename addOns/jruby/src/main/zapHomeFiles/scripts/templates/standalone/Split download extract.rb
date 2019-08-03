require 'java'

# Adjust the script to get join a file download which is split over several requests.
# This is useful if you have a JavaScript file download that downloads chunks of the file
# to reduce the risk of a broken connection.

extHist = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension("ExtensionHistory")
if (extHist != nil)
  
  File.open 'YOUR FILE PATH', 'wb' do |f|
    extHist.getSelectedHistoryReferences.each do |hr|
      content_type = hr.getHttpMessage.getResponseHeader.getHeader("Content-Type")
      url = hr.getHttpMessage.getRequestHeader.getURI.toString
      # additional filter to jump over files that are not desired - for example if you have a application
      # that is polling data open in background so and you just do not want to manually select them in the history.
      # if you do not want the filter, commment out the next line and the corresponding end
      if (content_type.include? 'octet-stream') && (url.include? 'www.example.com')
        payload = hr.getHttpMessage.getResponseBody.getBytes
        f.write payload if payload
      end
    end
  end
end
