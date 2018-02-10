"""
looks for parameter values that are reflected in the response.
Author: maradrianbelen.com
The scan function will be called for request/response made via ZAP, excluding some of the automated tools
Passive scan rules should not make any requests 
Note that new passive scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"
"""  
def compare(paramvalue_pair,msg): 
	reflected=''
	if len(paramvalue_pair.split('=',1))>1:
		value=paramvalue_pair.split('=',1)
		body=msg.getResponseBody().toString()
		header=msg.getResponseHeader().toString()
		if (value[1] in body or value[1] in header) and value[1] != '' and len(value[1])>7: 
			reflected=value
	return reflected

def scan(ps, msg, src): 
	alertTitle='Reflected HTTP GET parameter(s)'
	alertDesc='Reflected parameter value has been found. A reflected parameter values may introduce XSS vulnerability or HTTP header injection.'
	reflected_params=''
	URI=msg.getRequestHeader().getURI();
	query=URI.getQuery();
	if query:
		uriofreflected_param=URI.toString()
		paramvalue_pair=query.split('&');
		i=0;
		while(i<len(paramvalue_pair)):
			if(compare(paramvalue_pair[i],msg)):
				reflected_params=reflected_params  + compare(paramvalue_pair[i],msg)[0] + ','
			i=i+1;
		if(reflected_params):
			ps.raiseAlert(0, 2, alertTitle, alertDesc, uriofreflected_param, reflected_params, '', '', '', '', 0, 0, msg);
