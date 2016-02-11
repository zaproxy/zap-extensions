//it will generate and copy curl command based on the request
//released under the Apache v2.0 licence.
//You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//author:@haseebeqx

function invokeWith(msg) {
	string = "curl -i -s -k -X  '"+msg.getRequestHeader().getMethod()+"'  \\\n";
	header = msg.getRequestHeader().getHeadersAsString();
	header = header.split(msg.getRequestHeader().getLineDelimiter());
	for(i=0;i<header.length;i++){
		//blacklisting Host (other blacklisting should also specify here
		keyval = header[i].split(":");
		if(keyval[0].trim() != "Host")
			string += " -H '"+header[i].trim()+"' ";
	}
	string += " \\\n";
	body = msg.getRequestBody().toString();
	if(body.length() != 0){
		string += "--data-binary $'"+addSlashes(body)+"' \\\n";
	}
	string += "'"+msg.getRequestHeader().getURI().toString()+"'";
	selected = new java.awt.datatransfer.StringSelection(string);
	clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
	clipboard.setContents(selected,null);
	print (string);
}

function addSlashes(body){
	var a ={}
	a[body] = 1;
	return JSON.stringify(a).slice(2,-4);
}
