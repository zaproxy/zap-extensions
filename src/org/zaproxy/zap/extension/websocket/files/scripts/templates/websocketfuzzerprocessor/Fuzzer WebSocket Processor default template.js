// Auxiliary variables/constants needed for processing.
var count = 1;

// Called after injecting the payloads and before forward the message to the client or server.
function processMessage(utils, message) {
	// To obtain the list of payloads:
	//    utils.getPayloads()
	// To obtain original message:
	//    utils.getOriginalMessage()
	// To stop fuzzer:
	//    utils.stopFuzzer()
	// To increase the error count with a reason:
	//    utils.increaseErrorCount("Reason Error Message...")
	// To send a message, following redirects:
	//    utils.sendMessage("myMessageXyZ")
	// To send a message but do not show in results:
	//    utils.sendMessage(myMessage, false)

	// Process fuzzed message...
	message.payload = "123"
	count++;
}

