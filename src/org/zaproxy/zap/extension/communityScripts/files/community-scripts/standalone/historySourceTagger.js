// Running this script will cause ZAP to loop through all the entries in the history table.
// Entries in the table will be tagged (in the "tags" column) in the form:
// SRC_Proxied, SRC_Manual, SRC_Other
// The script can be run multiple times, history entries will only be tagged
// if they don't already have a tag that starts with TAG_PREFIX as defined below.
// Author: kingthorin+owaspzap@gmail.com
// 20160207: Initial release

extHist = org.parosproxy.paros.control.Control.getSingleton().
      getExtensionLoader().getExtension(org.parosproxy.paros.extension.history.ExtensionHistory.NAME);

TAG_PREFIX='SRC_';

if (extHist != null) {
  i=org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar("tagged_ref");// Check for global reference
  if(i==null) {
    i=1;// Global reference was null so 1
  }
  lastRef=extHist.getLastHistoryId();// Get current max history reference 
  while (i <= lastRef) {// Loop through the history table
    hr = extHist.getHistoryReference(i);
    if(i % 10 == 0 | i == 1 | i == lastRef) {// Progress update first, every 10, and last
      print('Checking ' + i);
    }
    if (hr) { 
      switch (hr.getHistoryType()) {
        case 1: type="Proxied"; break;
        case 15: type="Manual"; break;
        default: type="Other"; break;
      }
      newTag=TAG_PREFIX+type;
      theTags=hr.getTags();
      if(!theTags.contains(newTag)) {
        hr.addTag(newTag);
        try {
          extHist.notifyHistoryItemChanged(hr);// Trigger GUI update
        } catch (ex) { } //Ignore 
      }
    }
  i++;
  }
  org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar("tagged_ref",lastRef+1); // Set global reference
}
