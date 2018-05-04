WebSocket Fuzzer Processor scripts
=============================

Scripts that can control the WebSocket fuzzer and process the fuzzed WebSocket message.

## JavaScript template

```JavaScript
// Auxiliary variables/constants needed for processing.
var count = 1;

/**
 * Processes the fuzzed message (payloads already injected).
 * 
 * Called before forwarding the message to the client/server.
 * 
 * @param {WebSocketFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {WebSocketMessageDTO} message - The fuzzed message, that will be forward to the client/server.
 */
function processMessage(utils, message) {
    // To obtain the list of payloads:
    //    utils.getPayloads()
    // To obtain original message:
    //    utils.getOriginalMessage()
    // To stop fuzzer:
    //    utils.stopFuzzer()
    // To increase the error count with a reason:
    //    utils.increaseErrorCount("Reason Error Message...")
    // To send a WebSocket message:
    //    utils.sendMessage("myMessageXyZ")
    // To send a WebSocket message but do not show in results:
    //    utils.sendMessage(myMessage, false)

    // Process fuzzed message...
    message.payload = "123"
    count++;
}
```

## Parameters
| Name | Source |
| --- | --- |
| message | [WebSocketMessageDTO](https://github.com/zaproxy/zap-extensions/blob/master/src/org/zaproxy/zap/extension/websocket/WebSocketMessageDTO.java) |
| utils | [WebSocketFuzzerTaskProcessorUtils](https://github.com/zaproxy/zap-extensions/blob/master/src/org/zaproxy/zap/extension/websocket/fuzz/WebSocketFuzzerTaskProcessorUtils.java) |

