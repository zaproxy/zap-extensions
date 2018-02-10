// Cookie HttpOnly Check by freakyclown@gmail.com

function scan(ps, msg, src) 
{

    alertRisk = 1
    alertReliability = 2
    alertTitle = "Cookie set without HTTPOnly Flag(script)"
    alertDesc = "A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible."
    alertSolution = "Ensure that the HttpOnly flag is set for all cookies."

    cweId = 0
    wascId = 13

    url = msg.getRequestHeader().getURI().toString();
    headers = msg.getResponseHeader().getHeaders("Set-Cookie")
    
    if (headers != null)
    {
        re_noflag = /([Hh][Tt][Tt][Pp][Oo][Nn][Ll][Yy])/g
        if (!(re_noflag.test(headers)))
        {
            ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', '', alertSolution,headers, cweId, wascId, msg);
        }
    }
    
}
