import org.parosproxy.paros.core.scanner.Alert
import org.parosproxy.paros.core.scanner.Plugin
import org.parosproxy.paros.network.HttpMessage
import org.zaproxy.zap.extension.ascan.ScriptsActiveScanner

// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page.
 *
 * @param aScan -   the ActiveScan parent object that will do all the core interface tasks
 *                  (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *                  raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg   -   the HTTP Message being scanned. This is an HttpMessage object.
 */
void scanNode(ScriptsActiveScanner aScan, HttpMessage msg) {

    println('scan called for url=' + msg.getRequestHeader().getURI().toString())

    // Copy requests before reusing them
    msg = msg.cloneRequest()

    aScan.sendAndReceive(msg, false, false)

    // Test the responses and raise alerts as below

    // Check if the scan was stopped before performing lengthy tasks
    if (aScan.isStop()) {
        return
    }
    // Do lengthy task...

    // Raise less reliable alert (that is, prone to false positives) when in LOW alert threshold
    if (aScan.getAlertThreshold() == Plugin.AlertThreshold.LOW) {
        // ...
    }

    // Do more tests in HIGH attack strength
    // Expected values: "LOW", "MEDIUM", "HIGH", "INSANE"
    if (aScan.getAttackStrength() == Plugin.AttackStrength.HIGH) {
        // ...
    }
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 *
 * @param as    -   the ActiveScan parent object that will do all the core interface tasks
 *                  (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *                  raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg   -   the HTTP Message being scanned. This is an HttpMessage object.
 * @param param -   the name of the parameter being manipulated for this test/scan.
 * @param value -   the original parameter value.
 */
void scan(ScriptsActiveScanner aScan, HttpMessage msg, String param, String value) {
    // Debugging can be done using println like this
    println('scan called for url=' + msg.getRequestHeader().getURI().toString() +
            ' param=' + param + ' value=' + value)

    // Copy requests before reusing them
    msg = msg.cloneRequest()

    // Inject your payload
    aScan.setParam(msg, param, 'Your attack')

    aScan.sendAndReceive(msg, false, false);

    // Test the response here, and make other requests as required
    if (true) {	// Change to a test which detects the vulnerability
        aScan.raiseAlert(
                Alert.RISK_LOW,
                Alert.CONFIDENCE_LOW,
                'Active Vulnerability title',
                'Full description',
                msg.getRequestHeader().getURI().toString(),
                param,
                'Your attack',
                'Any other info',
                'The solution',
                'The evidence',
                0,
                0,
                msg)
    }
}