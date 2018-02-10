// Clacks Header Check by freakyclown@gmail.com

function scan(ps, msg, src) 
{

    alertRisk = 0
    alertReliability = 3
    alertTitle = "Server is running on CLACKS - GNU Terry Pratchett"
    alertDesc = "The web/application server is running over the CLACKS network, some say its turtles/IP, some says its turtles all the way down the layer stack."
    alertSolution = "Give the sys admin a high five and rejoice in the disc world."

    cweId = 200
    wascId = 13

    url = msg.getRequestHeader().getURI().toString();
    headers = msg.getResponseHeader().getHeaders("X-Clacks-Overhead")
    
    if (headers != null)
    {
        ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', '', alertSolution,headers, cweId, wascId, msg);
    }
    
}
