/*
 * Client-side scripts are run as functions on the target domain.
 * Thus, they should be written in Javascript.
 *
 * They receive `frontEndScanner` as a parameter, which exposes:
 *   - A `mailbox` attribute to subscribe to events happening in the page
 *   (more about that: https://github.com/zaproxy/front-end-tracker).
 *   - A `zapAlertConstants` attribute, with useful data to create alerts.
 *   - A `reportAlertToZap` function to create an Alert in ZAP.
*/

// Use the mailbox to react to any storage interaction with a lambda function
// which call `report()` every time the storage is set.
frontEndScanner.mailbox.subscribe('storage', (_, data) => {
  if (data.action === 'set') {
    report(data);
  }
});

function report(data) {
  // Use the `frontEndScanner.zapAlertConstants`, exposing some "internals"
  // of ZAP's `Alert` content.
  const confidence = frontEndScanner.zapAlertConstants.CONFIDENCE_HIGH;
  const risk = frontEndScanner.zapAlertConstants.RISK_INFO;

  // Craft the params that will be POSTed to ZAP.
  const alert = {
    confidence: confidence,
    description: 'Something has been written to a storage.',
    evidence: `key: ${data.key} has been set to value: ${data.value}`,
    name: 'Storage written.',
    risk: risk
  };

  // Call the function that will handle the communication with ZAP.
  frontEndScanner.reportAlertToZap(alert);
}
