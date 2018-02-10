// X-Powered-By finder by freakyclown@gmail.com

function scan(ps, msg, src) 
{

    alertRisk = 1
    alertReliability = 2
    alertTitle = "Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)(script)"
    alertDesc = "The web/application server is leaking information via one or more 'X-Powered-By' HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to."
    alertSolution = "Ensure that your web server, application server, load balancer, etc. is configured to suppress 'X-Powered-By' headers."

    cweId = 200
    wascId = 13

    url = msg.getRequestHeader().getURI().toString();
    headers = msg.getResponseHeader().getHeaders("X-Powered-By")
    
    if (headers != null)
    {
        ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', '', alertSolution,headers, cweId, wascId, msg);
    }
    
}
