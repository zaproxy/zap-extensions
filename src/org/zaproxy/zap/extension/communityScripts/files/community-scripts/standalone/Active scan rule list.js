// This script gives details about all of the active scan rules installed

// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

extAscan = org.parosproxy.paros.control.Control.getSingleton().
    getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.ascan.ExtensionActiveScan.NAME);

plugins = extAscan.getPolicyManager().getDefaultScanPolicy().getPluginFactory().getAllPlugin().toArray();

println('\n');

for (var i=0; i < plugins.length; i++) {
  try {
    println ('Plugin ID: ' + plugins[i].getId());
    println ('Name: ' + plugins[i].getName());
    println ('Desc: ' + plugins[i].getDescription());
    println ('Risk: ' + plugins[i].getRisk());
    println ('Soln: ' + plugins[i].getSolution());
    println ('Ref:  ' + plugins[i].getReference());
    println ('CWE:  ' + plugins[i].getCweId());
    println ('WASC:  ' + plugins[i].getWascId());
    println ('');
  } catch (e) {
    println (e);
  }
}
