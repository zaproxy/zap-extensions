// This script loops through all of the alerts - change it to do whatever you want to do :)
//
// This is a standalone script which you can run from the Script Console

extAlert = org.parosproxy.paros.control.Control.getSingleton().
    getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.alert.ExtensionAlert.NAME) 
if (extAlert != null) {
	var Alert = org.parosproxy.paros.core.scanner.Alert
	var alerts = extAlert.getAllAlerts()
	for (var i = 0; i < alerts.length; i++) {
		var alert = alerts[i]
		print (alert.uri)
		print ('\tName:\t' + alert.name)
		print ('\tRisk:\t' + Alert.MSG_RISK[alert.risk])
		print ('\tConfidence:\t' + Alert.MSG_CONFIDENCE[alert.confidence])
		// For more alert properties see https://static.javadoc.io/org.zaproxy/zap/2.7.0/org/parosproxy/paros/core/scanner/Alert.html
	}
}