Payload Processor scripts
=========================

Scripts that can change the payloads before being used in the fuzzer.

## JavaScript template

```JavaScript
// Auxiliary variables/constants for processing.
var id = 0;

/**
 * Processes the payload.
 * 
 * Called for each payload that needs to be processed.
 * 
 * @param {string} payload - The payload before being injected into the message.
 * @return {string} The payload processed.
 */
function process(payload) {
    // Do some processing to payload
    payload = payload + '-' + id;
    id++;

    return payload;
}
```

## Parameters
| Name | JavaDoc |
| --- | --- |
| payload | [String](https://docs.oracle.com/javase/7/docs/api/java/lang/String.html) |
