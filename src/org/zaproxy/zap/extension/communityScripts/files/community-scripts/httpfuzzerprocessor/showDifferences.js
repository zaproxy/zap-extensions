//A Fuzzer HTTP Processor script that compares the original Response with the fuzzed Response 
//and add the result to the state column!
//To remove all other states from the state column set the variable `removeOtherStatesFromStateColumn` to `true`.
//This might be useful if you want to order the column.
//Script needs Diff add-on
 
var DiffTool = Java.type("org.zaproxy.zap.extension.diff.diff_match_patch");
var key = "script.showDifferences.js";
var showResultInTable = true;
var removeOtherStatesFromStateColumn = false;
var original = null;

function processMessage(utils, message) {
	return message;
}

// Called after receiving the fuzzed message from the server
function processResult(utils, fuzzResult){	
	if(!original){
		original = responseAsString(utils.getOriginalMessage());
	}
	
	var fuzzed = responseAsString(fuzzResult.getHttpMessage());
	var diffList = createDiff(original, fuzzed);	
	var aggregatedDiff = aggregateDiff(diffList);	
	displayToStateColumn(fuzzResult, aggregatedDiff);
	return showResultInTable;
}

function responseAsString(httpMessage){
	var responseHeader = httpMessage.getResponseHeader().toString();
	var responseBody = httpMessage.getResponseBody().toString();
	return responseHeader + "\r\n" + responseBody;
}

function createDiff(original, fuzzed){
	var diffTool = new DiffTool();
	return diffTool.diff_main(original, fuzzed);
}

function displayToStateColumn(fuzzResult, aggregatedDiff){
	if(removeOtherStatesFromStateColumn){
		removeAllStates(fuzzResult);
	}	
	fuzzResult.addCustomState(key, "Sum: "+padLeft(aggregatedDiff.Sum) + "; Delta:" + aggregatedDiff.Delta);	
}

function removeAllStates(fuzzResult){
	for each (var key in fuzzResult.getCustomStates().keySet() ) {
		fuzzResult.removeCustomState(key);
	}	
}

function padLeft(value){
	var str = value + ""; 
	var pad = "00000000";
	return pad.substring(0, pad.length - str.length) + str;
}

function aggregateDiff(diffList){

	var sum = 0;
	var delta = "";
	for each (var diff in diffList) {
		if(diff.operation == "INSERT"){
			sum += diff.text.length();
			delta += "++|" + prepareDiffText(diff.text) + "|";
		}
		else if(diff.operation == "DELETE"){
			sum += diff.text.length();
			delta += "--|" + prepareDiffText(diff.text) + "|";
		}		
	} 

	return {
		Sum : sum,
		Delta : delta
	}
}

function prepareDiffText(text){
	text = text.replace("\r", "\\r");
	text = text.replace("\n", "\\n");
	return text
}
