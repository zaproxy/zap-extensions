// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    url = msg.getRequestHeader().getURI().toString();
    body = msg.getResponseBody().toString()
    alertRisk = [0,1,2,3,4] // risk: 0: info, 1: low, 2: medium, 3: high
    alertReliability = [0,1,2,3,4] // reliability: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
    alertTitle = ["An upload form appeared! (script)",""]
	alertDesc = ["An upload form exists. This isn't an issue, but it could be a lot of fun! Go check it out!.",""]
	alertSolution = ["This isn't an issue, but it could be a lot of fun!",""]
    cweId = [0,1]
    wascId = [0,1]
	
	uploadForm = /(type\s*=\s*['"]?file['"]?)/g
	
	if (uploadForm.test(body))
	{
		uploadForm.lastIndex = 0
		var founduploadForm = []
		while (comm = uploadForm.exec(body))
		{
			founduploadForm.push(comm[0]);
		}
		ps.raiseAlert(alertRisk[0], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', founduploadForm.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	}
}
