// Auxiliary variables/constants for processing.
var id = 0;

// Called for each payload that needs to be processed.
// The type of variable 'payload' is string.
function process(payload) {
	// Do some processing to payload
	payload = payload + '-' + id;
	id++;

	return payload;
}