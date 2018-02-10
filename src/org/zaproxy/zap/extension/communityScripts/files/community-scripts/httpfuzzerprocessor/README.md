HTTP Fuzzer Processor scripts
=============================

Scripts that can control the HTTP fuzzer and manage its results.

## JavaScript template

```JavaScript
// Auxiliary variables/constants needed for processing.
var count = 1;

/**
 * Processes the fuzzed message (payloads already injected).
 * 
 * Called before forwarding the message to the server.
 * 
 * @param {HttpFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {HttpMessage} message - The fuzzed message, that will be forward to the server.
 */
function processMessage(utils, message) {
    // To obtain the list of payloads:
    //    utils.getPayloads()
    // To obtain original message:
    //    utils.getOriginalMessage()
    // To stop fuzzer:
    //    utils.stopFuzzer()
    // To increases the error count with a reason:
    //    utils.increaseErrorCount("Reason Error Message...")
    // To send a message, following redirects:
    //    utils.sendMessage(myMessage)
    // To send a message, not following redirects:
    //    utils.sendMessage(myMessage, false)
    // To add a message previously sent to results:
    //    utils.addMessageToResults("Type Of Message", myMessage)
    // To add a message previously sent to results, with custom state:
    //    utils.addMessageToResults("Type Of Message", myMessage, "Key Custom State", "Value Custom State")
    // The states' value is shown in the column 'State' of fuzzer results tab

    // Process fuzzed message...
    message.getRequestHeader().setHeader("X-Unique-Id", count);
    count++;
}

/**
 * Processes the fuzz result.
 * 
 * Called after receiving the fuzzed message from the server.
 * 
 * @param {HttpFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {HttpFuzzResult} fuzzResult - The result of sending the fuzzed message.
 * @return {boolean} Whether the result should be accepted, or discarded and not shown.
 */
function processResult(utils, fuzzResult){
    // All the above 'utils' functions are available plus:
    // To raise an alert:
    //    utils.raiseAlert(risk, confidence, name, description)
    // To obtain the fuzzed message, received from the server:
    //    fuzzResult.getHttpMessage()

    var condition = true;
    if (condition)
        fuzzResult.addCustomState("Key Custom State", "Message Contains X")

    return true;
}

```

## Parameters
| Name | JavaDoc |
| --- | --- |
| message | [HttpMessage](http://www.zaproxy.org/2.5/javadocs/org/parosproxy/paros/network/HttpMessage.html) |

## Code Links
| Name | Source |
| --- | --- |
| fuzzResult | [HttpFuzzResult](https://github.com/zaproxy/zap-extensions/blob/beta/src/org/zaproxy/zap/extension/fuzz/httpfuzzer/HttpFuzzResult.java) |
| utils | [HttpFuzzerTaskProcessorUtils](https://github.com/zaproxy/zap-extensions/blob/beta/src/org/zaproxy/zap/extension/fuzz/httpfuzzer/HttpFuzzerTaskProcessorUtils.java) |

