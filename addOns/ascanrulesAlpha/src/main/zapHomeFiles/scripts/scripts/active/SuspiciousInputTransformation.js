/**
 * Hat tip to https://github.com/albinowax/ActiveScanPlusPlus/blob/master/src/burp/SuspectTransform.java.
 */

const ScanRuleMetadata = Java.type("org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata");
const CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");
const PolicyTag = Java.type("org.zaproxy.addon.commonlib.PolicyTag");
const RandomStringUtils = Java.type("org.apache.commons.lang3.RandomStringUtils");
const RandomUtils = Java.type("org.apache.commons.lang3.RandomUtils");
const CHECK_CONFIRM_COUNT = 2;
const SCAN_RULE_ID = "100044";

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: ${SCAN_RULE_ID}
name: Suspicious Input Transformation
description: >
  The application performed a suspicious input transformation that may indicate a security vulnerability.
  The input was transformed in an unexpected way, suggesting potential issues with input validation, encoding/decoding,
  or expression evaluation. This could indicate vulnerabilities such as server-side template injection,
  expression language injection, unicode normalization issues, or other input processing flaws that may be exploitable.
solution: >
  Review input validation and sanitization mechanisms. Ensure user input is properly escaped and validated
  before processing. Consider implementing strict input filtering to prevent injection attacks.
references: []
category: injection
risk: high
confidence: medium
cweId: 20  # CWE-20: Improper Input Validation
wascId: 20  # WASC-20: Improper Input Handling
alertTags:
  ${CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()}: ${CommonAlertTag.OWASP_2021_A03_INJECTION.getValue()}
  ${CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()}: ${CommonAlertTag.OWASP_2017_A01_INJECTION.getValue()}
  ${PolicyTag.PENTEST.getTag()}: ""
alertRefOverrides:
  ${SCAN_RULE_ID}-1:
    name: Suspicious Input Transformation - Quote Consumption
  ${SCAN_RULE_ID}-2:
    name: Suspicious Input Transformation - Arithmetic Evaluation
  ${SCAN_RULE_ID}-3:
    name: Suspicious Input Transformation - Expression Evaluation
    references:
      - https://portswigger.net/research/server-side-template-injection
  ${SCAN_RULE_ID}-4:
    name: Suspicious Input Transformation - Template Evaluation
    references:
      - https://portswigger.net/research/server-side-template-injection
  ${SCAN_RULE_ID}-5:
    name: Suspicious Input Transformation - EL Evaluation
    references:
      - https://portswigger.net/research/server-side-template-injection
  ${SCAN_RULE_ID}-6:
    name: Suspicious Input Transformation - Unicode Normalisation
    references:
      - https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/
  ${SCAN_RULE_ID}-7:
    name: Suspicious Input Transformation - URL Decoding Error
    references:
      - https://cwe.mitre.org/data/definitions/172.html
  ${SCAN_RULE_ID}-8:
    name: Suspicious Input Transformation - Unicode Byte Truncation
    references:
      - https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows
  ${SCAN_RULE_ID}-9:
    name: Suspicious Input Transformation - Unicode Case Conversion
    references:
      - https://www.unicode.org/charts/case/index.html
  ${SCAN_RULE_ID}-10:
    name: Suspicious Input Transformation - Unicode Combining Diacritic
    references:
      - https://codepoints.net/combining_diacritical_marks?lang=en
status: alpha
codeLink: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesAlpha/src/main/zapHomeFiles/scripts/scripts/active/SuspiciousInputTransformation.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-alpha/#id-100044
`);
}

function generateRandomString(length) {
  return RandomStringUtils.secure().nextAlphanumeric(length);
}

function generateRandomNumbers() {
  const x = RandomUtils.secure().randomInt(99, 10000);
  const y = RandomUtils.secure().randomInt(99, 10000);
  return { x, y, product: x * y };
}

const inputTransformationChecks = [
  {
    // Quote Consumption
    alertRef: SCAN_RULE_ID + "-1",
    transformFunction: function (originalValue) {
      const leftAnchor = generateRandomString(6);
      const rightAnchor = generateRandomString(6);
      return {
        attackPayload: leftAnchor + "''" + rightAnchor,
        expectedTransformedValues: [leftAnchor + "'" + rightAnchor],
      };
    }
  },
  {
    // Arithmetic Evaluation
    alertRef: SCAN_RULE_ID + "-2",
    transformFunction: function (originalValue) {
      const nums = generateRandomNumbers();
      return {
        attackPayload: nums.x + "*" + nums.y,
        expectedTransformedValues: [nums.product.toString()],
      };
    }
  },
  {
    // Expression Evaluation
    alertRef: SCAN_RULE_ID + "-3",
    transformFunction: function (originalValue) {
      const nums = generateRandomNumbers();
      return {
        attackPayload: "${" + nums.x + "*" + nums.y + "}",
        expectedTransformedValues: [nums.product.toString()],
      };
    }
  },
  {
    // Template Evaluation
    alertRef: SCAN_RULE_ID + "-4",
    transformFunction: function (originalValue) {
      const nums = generateRandomNumbers();
      return {
        attackPayload: "@(" + nums.x + "*" + nums.y + ")",
        expectedTransformedValues: [nums.product.toString()],
      };
    }
  },
  {
    // EL Evaluation
    alertRef: SCAN_RULE_ID + "-5",
    transformFunction: function (originalValue) {
      const nums = generateRandomNumbers();
      return {
        attackPayload: "%{" + nums.x + "*" + nums.y + "}",
        expectedTransformedValues: [nums.product.toString()],
      };
    }
  },
  {
    // Unicode Normalisation
    alertRef: SCAN_RULE_ID + "-6",
    transformFunction: function (originalValue) {
      const leftAnchor = generateRandomString(6);
      const rightAnchor = generateRandomString(6);
      return {
        attackPayload: leftAnchor + "\u212a" + rightAnchor,
        expectedTransformedValues: [leftAnchor + "K" + rightAnchor],
      };
    }
  },
  {
    // URL Decoding Error
    alertRef: SCAN_RULE_ID + "-7",
    transformFunction: function (originalValue) {
      const leftAnchor = generateRandomString(6);
      const rightAnchor = generateRandomString(6);
      return {
        attackPayload: leftAnchor + "\u0391" + rightAnchor,
        expectedTransformedValues: [leftAnchor + "N\u0011" + rightAnchor],
      };
    }
  },
  {
    // Unicode Byte Truncation
    alertRef: SCAN_RULE_ID + "-8",
    transformFunction: function (originalValue) {
      const leftAnchor = generateRandomString(6);
      const rightAnchor = generateRandomString(6);
      return {
        attackPayload: leftAnchor + "\uCF7B" + rightAnchor,
        expectedTransformedValues: [leftAnchor + "{" + rightAnchor],
      };
    }
  },
  {
    // Unicode Case Conversion
    alertRef: SCAN_RULE_ID + "-9",
    transformFunction: function (originalValue) {
      const leftAnchor = generateRandomString(6);
      const rightAnchor = generateRandomString(6);
      return {
        attackPayload: leftAnchor + "\u0131" + rightAnchor,
        expectedTransformedValues: [leftAnchor + "I" + rightAnchor],
      };
    }
  },
  {
    // Unicode Combining Diacritic
    alertRef: SCAN_RULE_ID + "-10",
    transformFunction: function (originalValue) {
      const rightAnchor = generateRandomString(6);
      return {
        attackPayload: "\u0338" + rightAnchor,
        expectedTransformedValues: ["\u226F" + rightAnchor],
      };
    }
  },
];

function scan(as, msg, param, value) {
  const originalResponse = msg.getResponseBody().toString();
  const checksCount =
    as.getAttackStrength() == "LOW" ? 6 : inputTransformationChecks.length;

  for (let i = 0; i < checksCount; i++) {
    if (as.isStop()) {
      return;
    }

    const check = inputTransformationChecks[i];
    let confirmedTransformation = false;

    // Perform multiple attempts to confirm the transformation
    for (let attempt = 0; attempt < CHECK_CONFIRM_COUNT; attempt++) {
      if (as.isStop()) {
        return;
      }

      // Generate the attack payload and expected values
      const transformFunctionResult = check.transformFunction(value);
      const attackPayload = transformFunctionResult.attackPayload;
      const expectedValues = transformFunctionResult.expectedTransformedValues;

      // Send the request with the attack payload
      const testMsg = msg.cloneRequest();
      as.setParam(testMsg, param, attackPayload);
      as.sendAndReceive(testMsg, false, false);

      // Check if the response contains any of the expected values
      const attackResponse = testMsg.getResponseBody().toString();
      let responseContainsTransformedValue = false;
      for (let j = 0; j < expectedValues.length; j++) {
        const expectedValue = expectedValues[j];
        if (
          attackResponse.indexOf(expectedValue) !== -1 &&
          originalResponse.indexOf(expectedValue) === -1
        ) {
          responseContainsTransformedValue = true;
          if (attempt === CHECK_CONFIRM_COUNT - 1) {
            // Response contained transformed value in all attempts, raise alert
            as.newAlert(check.alertRef)
              .setParam(param)
              .setAttack(attackPayload)
              .setEvidence(expectedValue)
              .setMessage(testMsg)
              .raise();
            confirmedTransformation = true;
          }
          break;
        }
      }
      if (!responseContainsTransformedValue) {
        // Response does not contain any expected value, no need to retry for confirmation
        break;
      }
    }

    if (confirmedTransformation) {
      // Matched one check, unlikely that others will match too, so skip them
      break;
    }
  }
}
