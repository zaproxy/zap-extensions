// CreditCard Finder by freakyclown@gmail.com

function scan(ps, msg, src)
{
    // lets set up some stuff we are going to need for the alert later if we find a credit card
    url = msg.getRequestHeader().getURI().toString();
    body = msg.getResponseBody().toString()
    alertRisk = [0,1,2,3] //1=informational, 2=low, 3=medium, 4=high
    alertReliability = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    alertTitle = ["Credit Card Number(s) Disclosed (script)",
		  ""]
    alertDesc = ["Credit Card number(s) was discovered.",
		""]
    alertSolution = ["why are you showing Credit and debit card numbers?",
		    ""]
    cweId = [0,1]
    wascId = [0,1]


    // lets make some regular expressions for well known credit cards
    // regex must appear within /( and )/g

   
    re_visa = /([3-5][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})/g //visa or mastercard
    re_amex = /(3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5})/g //amex
    re_disc = /(6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})/g //discovery
    re_diner = /(3(?:0[0-5]|[68][0-9])[0-9]{11})/g //dinersclub
    re_jcb = /((?:2131|1800|35d{3})d{11})/g //jcb

	// now lets put all of those into a nice array so we can loop over it
	cards = [re_visa,re_amex,re_disc,re_diner,re_jcb]


	// here we are going to check the content type and skip over things that
	// wont contain credit cards like jpegs and such like
     contenttype = msg.getResponseHeader().getHeader("Content-Type")
	unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash', 'application/pdf']
	
	if (unwantedfiletypes.indexOf(""+contenttype) >= 0) 
	{
		// if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    		return
	}else{
	// right lets run our scan by looping over all the cards in the array above and testing them against the
	// body of the response    
	for (var i=0; i < cards.length; i++)
		{		
		if (cards[i].test(body)) 
			{
			cards[i].lastindex = 0
			var foundCard = []
				while (comm = cards[i].exec(body))
				{
					// perform luhn check this checks to make sure its a valid cc number!
					if (luhncheck(comm[0]) ==0){
						foundCard.push(comm[0]);}
				}
			if (foundCard.length !=0){
			ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', foundCard.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);}
			}

      	}

	}
}
function luhncheck(value){
	// this function is based on work done by DiegoSalazar on github (https://gist.github.com/DiegoSalazar)
	var nCheck = 0, nDigit = 0, bEven = false;
	value = value.replace(/\D/g, "");
 
	for (var n = value.length - 1; n >= 0; n--) {
		var cDigit = value.charAt(n),
			  nDigit = parseInt(cDigit, 10);
 
		if (bEven) {
			if ((nDigit *= 2) > 9) nDigit -= 9;
		}
 
		nCheck += nDigit;
		bEven = !bEven;
	}
	
	// debug here print ("value: " + value + "  lunh: " +nCheck % 10);
	return (nCheck % 10);
}
