// The parseParameter function will typically be called for every page and 
// the setParameter function is called by each active plugin to bundle specific attacks

// Note that new custom input vector scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

/*
This variant script can be used as an alternative to the default JSON input vectors
when one only wants to scan the string fields of the JSON object, not integers.

Input vectors will be located and set recursively and objects containing up to three
layers of objects, lists and strings seem to work as intended.
*/

function parseParameters(helper, msg) {
	//we're only interested in JSON requests with non-empty POST bodies
	header = msg.getRequestHeader()
	if(!header.getHeader("Content-Type")
		|| !header.getHeader("Content-Type").trim().equalsIgnoreCase("application/json")
		|| header.getMethod() != "POST"
		|| msg.getRequestBody().length() == 0
	){
		return;
	}

	body = msg.getRequestBody().toString();
	try{
		obj = JSON.parse(body);
	}
	catch(err){
		print("Parsing message body failed: " + err.message);
		return;
	}
	recursive_parse(helper, obj, "Object");
}

function recursive_parse(helper, obj, path){
	if (typeof(obj) == "number"){
		//skipping this is why I wrote this script!
	}else if(typeof(obj) == "string"){
		//here the parameter is added with the name being a JSON
		//list of keys that act as the JSON path to the input vector
		helper.addParamPost(path, obj);
	}else {
		for (k in obj){
			recursive_parse(helper, obj[k], path + "." + k)
		}
	}
	//are there other cases that have been missed?
}
function setParameter(helper, msg, param, value, escaped) {
	try{
		obj = JSON.parse(msg.getRequestBody().toString());
		//get the path from the parameter name, ignore the "Object"-part
		path = param.split('.').slice(1);
		//this may fail if "param" has been edited since parsing
		recursive_set(obj, path, value);
	}
	catch (err){
		print("Setting parameter value failed: " + err.message);
		return;
	}
	msg.getRequestBody().setBody(JSON.stringify(obj));
}

function recursive_set(obj, path, value){
	//print(JSON.stringify(obj) + " : " + JSON.stringify(path))
	if (path.length == 0){
		//stop recursing when the path is consumed
		return value;
	}
	obj[path[0]] = recursive_set(obj[path[0]], path.slice(1), value);
	return obj;
}
