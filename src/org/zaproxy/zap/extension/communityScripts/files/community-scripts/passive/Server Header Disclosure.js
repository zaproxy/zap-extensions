// Server Header Check by freakyclown@gmail.com

function scan(ps, msg, src) 
{

    alertRisk = 1
    alertReliability = 2
    alertTitle = "Server Leaks Version Information via 'Server' HTTP Response Header Field(script)"
    alertDesc = "The web/application server is leaking version information via the 'Server' HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to."
    alertSolution = "Ensure that your web server, application server, load balancer, etc. is configured to suppress the 'Server' header or provide generic details."

    cweId = 200
    wascId = 13

    url = msg.getRequestHeader().getURI().toString();
    if (msg) 
	{
		headers = msg.getResponseHeader().getHeaders("Server")
		
	  if (headers != null)
		{
       	 ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', '', alertSolution,headers, cweId, wascId, msg);
		}  
	 }
    
}
