// Encryption Hash Finder by freakyclown@gmail.com

function scan(ps, msg, src)
{
    url = msg.getRequestHeader().getURI().toString();
    body = msg.getResponseBody().toString()
    alertRisk = [0,1,2,3] //1=informational, 2=low, 3=medium, 4=high
    alertReliability = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    alertTitle = ["Wordpress hash Disclosed (script)",
		  "Sha512 hash Disclosed (script)",
		  "phpBB3 hash Disclosed (script)",
		  "Joomla hash Disclosed (script)",
		  "MySQL(old) hash Disclosed (script)",
		  "Drupal hash Disclosed (script)",
		  "Blowfish hash Disclosed (script)",
		  "VBulletin hash Disclosed (script)",
		  "MD4/MD5 hash Disclosed (script)",
		  ""]
    alertDesc = ["A Wordpress hash was discovered.",
		 "A Sha512 hash was discovered.",
		 "A phpBB3 hash was discovered.",
		 "A Joomla hash was discovered.",
		 "A MySQL(old) hash was discovered.",
		 "A Drupal hash was discovered.",
		 "A Blowfish hash was discovered.",
		 "A VBulletin hash was discovered.",
		 "A MD4/MD5 hash Disclosed was discovered",
		""]
    alertSolution = ["Ensure that hashes that are used to protect credentials or other resources are not leaked by the web server or database. There is typically no requirement for password hashes to be accessible to the web browser.",
		    ""]
    cweId = [0,1]
    wascId = [0,1]



	// regex must appear within /( and )/g

    wordpress = /($P$S{31})/g
    sha512 = /($6$w{8}S{86})/g
    phpbb3 = /($H$S{31})/g
    joomla = /(([0-9a-zA-Z]{32}):(w{16,32}))/g
    mysqlold = /([0-7][0-9a-f]{7}[0-7][0-9a-f]{7})/g
    drupal = /($S$S{52})/g
    blowfish = /($2a$8$(.){75})/g
    vbull = /(([0-9a-zA-Z]{32}):(S{3,32}))/g //vbulletin
    md45 = /([a-f0-9]{32})/g //md4 and md5 and a bunch of others like tiger
	
    if (msg) 
	
      {        
	if (wordpress.test(body)) 
	  {
	    wordpress.lastIndex = 0
	    var foundwordpress = []
            while (comm = wordpress.exec(body)) 
	      {
               foundwordpress.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[1], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', foundwordpress.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	   
	if (sha512.test(body)) 
	  {
	    sha512.lastIndex = 0
	    var foundsha512 = []
            while (comm = sha512.exec(body)) 
	      {
               foundsha512.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[1], alertReliability[2], alertTitle[1], alertDesc[1], url, '', '', foundsha512.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (phpbb3.test(body)) 
	  {
	    phpbb3.lastIndex = 0
	    var foundphpbb3 = []
            while (comm = phpbb3.exec(body)) 
	      {
               foundphpbb3.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[1], alertReliability[2], alertTitle[2], alertDesc[2], url, '', '', foundphpbb3.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }



	if (mysqlold.test(body)) 
	  {
	    mysqlold.lastIndex = 0
	    var foundmysqlold = []
            while (comm = mysqlold.exec(body)) 
	      {
               foundmysqlold.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[1], alertReliability[2], alertTitle[3], alertDesc[3], url, '', '', foundmysqlold.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (joomla.test(body)) 
	  {
	    joomla.lastIndex = 0
	    var foundjoomla = []
            while (comm = joomla.exec(body)) 
	      {
               foundjoomla.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[1], alertReliability[2], alertTitle[4], alertDesc[4], url, '', '', foundjoomla.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (drupal.test(body)) 
	  {
	    drupal.lastIndex = 0
	    var founddrupal = []
            while (comm = drupal.exec(body)) 
	      {
               founddrupal.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[1], alertReliability[2], alertTitle[5], alertDesc[5], url, '', '', founddrupal.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	   
	if (blowfish.test(body)) 
	  {
	    blowfish.lastIndex = 0
	    var foundblowfish = []
            while (comm = blowfish.exec(body)) 
	      {
               foundblowfish.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[1], alertReliability[2], alertTitle[6], alertDesc[6], url, '', '', foundblowfish.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (vbull.test(body)) 
	  {
	    vbull.lastIndex = 0
	    var foundvbull = []
            while (comm = vbull.exec(body)) 
	      {
               foundvbull.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[1], alertReliability[2], alertTitle[7], alertDesc[7], url, '', '', foundvbull.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

  
	if (md45.test(body)) 
	  {
	    md45.lastIndex = 0
	    var foundmd45 = []
            while (comm = md45.exec(body)) 
	      {
               foundmd45.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[1], alertReliability[1], alertTitle[8], alertDesc[8], url, '', '', foundmd45.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
     }

}
