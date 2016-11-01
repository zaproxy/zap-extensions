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