// This script gives details about all of the active scan rules installed

extAscan = org.parosproxy.paros.control.Control.getSingleton().
    getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.ascan.ExtensionActiveScan.NAME);

plugins = extAscan.getPolicyManager().getDefaultScanPolicy().getPluginFactory().getAllPlugin().toArray();

print('\n');

for (var i=0; i < plugins.length; i++) {
  try {
    print ('Plugin ID: ' + plugins[i].getId());
    print ('Name: ' + plugins[i].getName());
    print ('Desc: ' + plugins[i].getDescription());
    print ('Risk: ' + plugins[i].getRisk());
    print ('Soln: ' + plugins[i].getSolution());
    print ('Ref:  ' + plugins[i].getReference());
    print ('CWE:  ' + plugins[i].getCweId());
    print ('WASC:  ' + plugins[i].getWascId());
    print ('');
  } catch (e) {
    print (e);
  }
}
