import groovy.transform.Field

// Auxiliary variables/constants for processing.
@Field long id = 0

/**
 * Processes the payload.
 *
 * Called for each payload that needs to be processed.
 *
 * @param {string} payload - The payload before being injected into the message.
 * @return {string} The payload processed.
 */
String process(String payloadValue) {
    // Do some processing to payload
    def payload = payloadValue + '-' + id
    id++
    return payload
}
