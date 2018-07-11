/*
 * When storage is written to, check if the written value is a JWT token.
 */

frontEndScanner.mailbox.subscribe('storage', (_, storageEntry) => {
  // A storage entry has the following form:
  // {key: 'foo', value: 'bar', action: 'get|remove|set'}
  if (storageEntry.action === 'set') {
    verify(storageEntry);
    verifySubEntries(storageEntry);
  }
});

function verify(storageEntry) {
  const potentialToken = storageEntry.value;
  const tokenContent = _parseJwt(potentialToken);

  if (!tokenContent) { return; }

  _reportJwtToken(storageEntry, tokenContent);

  if (tokenContent.header.alg === 'HS256') {
    _reportWeakAlgorithm(storageEntry, tokenContent);
  } else if (tokenContent.header.alg === 'none') {
    _reportNoneAlgorithm(storageEntry, tokenContent);
  }
}

// In case of nested entries (a storage entry having a stringified object as value)
// scan the first level of depth for a token.
function verifySubEntries(storageEntry) {
  const storageEntryValue = (entryValue => {
    try {
      return JSON.parse(entryValue);
    } catch (e) {
      return false;
    }
  })(storageEntry.value);

  if (storageEntryValue) {
    Object.keys(storageEntryValue).forEach(key => {
      verify({
        key: key,
        value: storageEntryValue[key]
      });
    });
  }
}

function _parseJwt(token) {
  try {
    var result = token
      .split('.')
      .map(x => x.replace('-', '+'))
      .map(x => x.replace('_', '/'))
      .map(window.atob);

    // Get rid of the last element: we will not check integrity.
    result.splice(-1, 1);

    return {
      header: JSON.parse(result[0]),
      payload: JSON.parse(result[1])
    }
  } catch (e) {
    return false;
  }
}

function _reportJwtToken(storageEntry, token) {
  _reportAlert(
    frontEndScanner.zapAlertConstants.CONFIDENCE_HIGH,
    'A JWT token has been found in a storage.',
    `key: '${storageEntry.key}' has been set to value: '${storageEntry.value}', decrypting to ${JSON.stringify(token)}`,
    'JWT token found.',
    frontEndScanner.zapAlertConstants.RISK_INFO
  );
}

function _reportWeakAlgorithm(storageEntry, token) {
  _reportAlert(
    frontEndScanner.zapAlertConstants.CONFIDENCE_HIGH,
    "A JWT token is using the HS256 algorithm, considered insecure.",
    `token stored at key: '${storageEntry.key}' has the following header: ${JSON.stringify(token.header)}`,
    "JWT token uses a weak algorithm.",
    frontEndScanner.zapAlertConstants.RISK_LOW
  );
}

function _reportNoneAlgorithm(storageEntry, token) {
  _reportAlert(
    frontEndScanner.zapAlertConstants.CONFIDENCE_HIGH,
    "A JWT token is using the 'none' algorithm.",
    `token stored at key: '${storageEntry.key}' has the following header: ${JSON.stringify(token.header)}`,
    "JWT token uses 'none' algorithm.",
    frontEndScanner.zapAlertConstants.RISK_HIGH
  );
}

class Alert {
  constructor(confidence, description, evidence, name, risk) {
    this.confidence = confidence;
    this.description = description;
    this.evidence = evidence;
    this.name = name;
    this.risk = risk;
  }
}

function _reportAlert(confidence, description, evidence, name, risk) {
  frontEndScanner.reportAlertToZap(
    new Alert(confidence, description, evidence, name, risk)
  );
}
