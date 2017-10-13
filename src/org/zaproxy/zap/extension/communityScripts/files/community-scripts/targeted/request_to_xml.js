// A Script to convert Request body in normal form or JSON to XML
// and set Content type to application/xml.
// it uses manual request editor where you can edit the converted request 
// it is not an automated tool in finding XXE 
// it may be helpful in finding XXE or other vulnerabilities.
// this script is intended to  act as an assistant
// you can  add anything like [!ENTITY] to test in detail
// released under the Apache v2.0 licence.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Author : @haseebeqx (GitHub, Twitter)
// tested on: ZAP 2.4.1
// note : due to a bug in mozilla Rhino  bdy.charAt(j) had to be replaced with String.fromCharCode(bdy.charAt(j)). so in future (or in Nashorn) you may have to change it back
// rule1: pure JSON , no CODE
// rule2: correct body (make edits only after conversion)

function invokeWith(msg) {
	body = '<?xml version="1.0" encoding="UTF-8"?>\n';
	reqb = msg.getRequestBody().toString(); 
	reqh = msg.getRequestHeader().getURI().toString();
	if(isJson(reqb)){
		body += jsonToXML(reqb);
	}
	else if(ismultipart(msg.getRequestHeader())){
		js = multiToJson(msg);
		body += jsonToXML(js);
	}
	else{
		js = bodyToJson(reqb);
		body += jsonToXML(js);
	}
	msg.setRequestBody(body);
	header = msg.getRequestHeader();
	header.setHeader(org.parosproxy.paros.network.HttpRequestHeader.CONTENT_TYPE,"application/xml");
	header.setHeader(org.parosproxy.paros.network.HttpRequestHeader.CONTENT_LENGTH,body.length);
	msg.setRequestHeader(header);
	ext = new org.parosproxy.paros.extension.history.ExtensionHistory;
	man = ext.getResendDialog();
	man.setMessage(msg.cloneRequest());
	man.setVisible(true);
}

function isJson(str){
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

function bodyToJson(body){
	result = {};
	tm = decodeURIComponent(body);
	if(tm.indexOf('[') > -1 && tm.indexOf('[') > -1){
		body = body.split('&');
		for(i=0; i<body.length;i++){
			body[i] = decodeURIComponent(body[i]);
			out = "";
			bdy = body[i];
			opend = false;
			len = bdy.length();
			first = true;
			for(j=0;j<len;j++){
				if(first){
					out += '{ "'
					af = '' ;			
					while(String.fromCharCode(bdy.charAt(j)) != '[' && String.fromCharCode(bdy.charAt(j)) != '=' ){
						if(j == len)
							break;
						out += String.fromCharCode(bdy.charAt(j))
						j++;
					}
					out += '" :';
					af += '} ';
					first = false;
				}
				if(String.fromCharCode(bdy.charAt(j)) == '=' && !opend){
					j++;
					out += '"'+bdy.substring(j,len)+'"';
					break;
					continue;
				}	
				else if(String.fromCharCode(bdy.charAt(j)) == '[' && !opend){
					opend = true;
					out += '{ "';
					if(String.fromCharCode(bdy.charAt(j+1)) == ']' && String.fromCharCode(bdy.charAt(j+2)) == '='){
						j += 2;
						out += '"'+bdy.substring(j,len)+'"';
						af += '} '
						break;
					}
					continue;
				}
				else if(String.fromCharCode(bdy.charAt(j)) == ']'){
					out += '" :';
					af += " }"
					opend = false;
					continue;
				}
				else if(opend){
					out += String.fromCharCode(bdy.charAt(j))
					continue;
				}
				else {
					//debug
				}
					
			}
				out += af
				out = JSON.parse(out);
			result = mergeJson(out,result);
		}
	}
	else{
		pairs = body.split('&');
		pairs.forEach(function(i, pair){
			pair = pair.split('=');
			result[pair[0]] = decodeURIComponent(pair[1]||'');
			});	
	}
return result;	
}


function jsonToXML(js){
	xml = "";
	for( key in js){
		if( js[key] == null){
			xml += js[key];
		}
		else if(typeof js[key] == "object"){
			xml += toXml(key,jsonToXML(js[key]),1);
		}
		else {
			xml += toXml(key,js[key],null);
		}
	}
	return xml;
}

function toXml(key,value,att){ //pretify
	if(att == null)
		return ("<"+key+">"+value+"</"+key+">\n");
	else{
		if(value.slice(-1) == '\n')
			value = value.substring(0,value.length-1);
		return ("<"+key+">\n "+value+" \n</"+key+">\n");
		}
}
function multiToJson(msg){
		type =  msg.getRequestHeader().getHeader(org.parosproxy.paros.network.HttpRequestHeader.CONTENT_TYPE);
		delim =  type.substring(type.search("=")+1,type.length());
		h = msg.getRequestBody().toString().split("--"+delim);
		k=0;
		names = [];
		values = [];
		out = "";
		for(i =1 ; i<h.length-1;i++){
			j = h[i].split(msg.getRequestHeader().getLineDelimiter());
			nameField = j[1].substring( j[1].search("name")+5,j[1].length());
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
			values[k] = addSlashes(values[k].substring(0,values[k].length-1));
			k++;		
		}
		result = {};
		for(i=0; i < k;i++){
			if(names[i].indexOf('[') > -1 && names[i].indexOf('[') > -1){
				bdy = names[i];
				len = bdy.length();
				af = "}"
				out = '{ "';
				opened = false;
				first = true;
				for(ii=0;ii<len;ii++){
					if(first){
						while(String.fromCharCode(bdy.charAt(ii)) != '[' && ii < len){
							out += String.fromCharCode(bdy.charAt(ii));
							ii++;	
						}
					first = false;
					out += '" '
					}
					if(String.fromCharCode(bdy.charAt(ii)) == '[' && !opened ){
						out += ' :{ "' ;
						opened = true;
						continue;
					} 
					if(String.fromCharCode(bdy.charAt(ii)) == ']' && opened){
						out += '"';
						af += '}';
						opened = false;
						continue;
					}
					if(opened){
						out += String.fromCharCode(bdy.charAt(ii));
					}
				}
				out += ':"'+values[i]+'"'+af;
				out = JSON.parse(out);
				result = mergeJson(out,result);
			}
			else {
				out 	 = JSON.parse('{ "'+names[i]+'" : "'+values[i]+'" }');
				result = mergeJson(out,result);
			}
		}
	return result;
}

function mergeJson(js1,js2){
	for (key in js1){
		if(js2.hasOwnProperty(key)){
			if(js2[key] != null && typeof js2[key] == "object"){
				mergeJson(js1[key],js2[key]);
			}
			else{
					js2[key] = {key:[js1[key],js2[key]]};
			}
		}
		else{
			js2[key] = js1[key]
		}
	}
	return js2;
}

function addSlashes(body){
	var a ={}
	a[body] = 1;
	return JSON.stringify(a).slice(2,-4);
}
