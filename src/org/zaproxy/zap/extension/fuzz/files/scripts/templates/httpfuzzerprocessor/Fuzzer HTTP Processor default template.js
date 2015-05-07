// Auxiliary variables/constants needed for processing.
var count = 1;

// Called after injecting the payloads and before forward the message to the server.
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

// Called after receiving the fuzzed message from the server
function processResult(utils, fuzzResult){
	// All the above 'utils' functions are available plus:
	// To raise an alert:
	//    utils.raiseAlert(risk, confidence, name, description)
	// To obtain the fuzzed message, received from the server:
	//    fuzzResult.getMessage()

	var condition = true;
	if (condition)
		fuzzResult.addCustomState("Key Custom State", "Message Contains X")
	
	// Returns true to accept the result, false to discard and not show it
	return true;
}
