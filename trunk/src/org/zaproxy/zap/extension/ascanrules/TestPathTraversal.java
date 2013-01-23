/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * 
 * a scanner that looks for Path Traversal vulnerabilities
 *
 */
public class TestPathTraversal extends AbstractAppParamPlugin {
	
	private static final String NON_EXISTANT_FILENAME = "thishouldnotexistandhopefullyitwillnot";

	/**
	 * the various (prioritised) prefixes to try, for each of the local file targets below
	 */
	private static final String [] LOCAL_FILE_TARGET_PREFIXES = {
		"/",
		"\\",
		"/../../../../../../../../../../../../../../../../../",
		"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
		"../../../../../../../../../../../../../../../..",
		"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
		"",
		"\\..\\..\\",
		"./",
		"../",
		"/../../",
		"../../",
		"/..",
		"/../",
		"/../..",
		"/./",
		"\\",
		".\\",
		"..\\",
		"..\\..\\",
		"\\..",
		"\\..\\",
		"\\..\\..",
		"\\.\\",
		"file://",
		"fiLe://",
		"file:",
		"fiLe:",
		"FILE:",
		"FILE://"
	};
	
	/**
	 * the various (prioritised) local file targets to look for (prefixed by the prefixes above)
	 */
	private static final String [][] LOCAL_FILE_TARGETS_AND_PATTERNS = {
		{"etc/passwd",			"root:.:0:0"},		// Dot used to match 'x' or '!' (used in AIX)
		{"Windows\\system.ini",	"\\[drivers\\]"},
		{"WEB-INF/web.xml",		"</web-app>"},
		{"etc\\passwd",			"root:.:0:0"},
		{"Windows/system.ini",	"\\[drivers\\]"},
		{"WEB-INF\\web.xml",	"</web-app>"}
	};
	
	/**
	 * details of the vulnerability which we are attempting to find
	 */
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_33");
    
    /**
     * the logger object
     */
    private static Logger log = Logger.getLogger(TestPathTraversal.class);

    /**
     * returns the plugin id 
     */
    @Override
    public int getId() {
        return 6;
    }

    /**
     * returns the name of the plugin
     */
    @Override
    public String getName() {
    	if (vuln != null) {
    		return vuln.getAlert();
    	}
        return "Path traversal";
    }

    @Override
    public String[] getDependency() {
        return null;
    }

    @Override
    public String getDescription() {
    	if (vuln != null) {
    		return vuln.getDescription();
    	}
    	return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
    	if (vuln != null) {
    		return vuln.getSolution();
    	}
    	return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
    	if (vuln != null) {
    		StringBuilder sb = new StringBuilder();
    		for (String ref : vuln.getReferences()) {
    			if (sb.length() > 0) {
    				sb.append('\n');
    			}
    			sb.append(ref);
    		}
    		return sb.toString();
    	}
    	return "Failed to load vulnerability reference from file";
    }

    @Override
    public void init() {

    }

    /**
     * scans all GET and POST parameters for Path Traversal vulnerabilities
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {
    
    	try {
    		//figure out how aggressively we should test
    		
    		// The number of prefixes to try
    		int prefixCount = 0;
    		// Number of prefixs on our url filename as a file to be included
    		int prefixCountOurUrl = 0;
    		// Number of targets to try
    		int targetCount = 0;
    		
    		//DEBUG only
    		//this.setAttackStrength(AttackStrength.INSANE);

    		if (log.isDebugEnabled()) {
    			log.debug("Attacking at Attack Strength: "+ this.getAttackStrength());
    		}

    		switch (this.getAttackStrength()) {
    		case LOW:
    			// This works out as a total of 7 reqs / param
				prefixCount = 2;
				targetCount = LOCAL_FILE_TARGETS_AND_PATTERNS.length / 2;
				prefixCountOurUrl = 0;
				break;
    		case MEDIUM:
    			// This works out as a total of 13 reqs / param
				prefixCount = 4;
				targetCount = LOCAL_FILE_TARGETS_AND_PATTERNS.length / 2;
				prefixCountOurUrl = 0;
				break;
    		case HIGH:
    			// This works out as a total of 26 reqs / param
				prefixCount = 6;
				targetCount = LOCAL_FILE_TARGETS_AND_PATTERNS.length / 2;
				prefixCountOurUrl = 1;
				break;
    		case INSANE:
    			// This works out as a total of 211(!) reqs / param
				prefixCount = LOCAL_FILE_TARGET_PREFIXES.length;
				targetCount = LOCAL_FILE_TARGETS_AND_PATTERNS.length;
				prefixCountOurUrl = LOCAL_FILE_TARGET_PREFIXES.length;
				break;
    		default:
    			// Default to off
    		}
    		
			Matcher matcher = null;
			
			if (log.isDebugEnabled()) {
				log.debug("Checking ["+getBaseMsg().getRequestHeader().getMethod() + "] [" + 
						getBaseMsg().getRequestHeader().getURI() +"], parameter ["+ param + "] for Path Traversal to local files");
			}
		    
			//for each local prefix in turn
			//note that depending on the AttackLevel, the number of prefixes that we will try changes.
	        for (int h=0; h < prefixCount; h++) {
	        	String prefix=LOCAL_FILE_TARGET_PREFIXES[h];
	        	//for each target in turn
	        	//note: regardless of the specified Attack Strength, we want to try all files name here 
	        	//(just for a limited number of prefixes)
				for (int i=0; i < targetCount; i++) {
					String target=LOCAL_FILE_TARGETS_AND_PATTERNS[i][0];
					
					//get a new copy of the original message (request only) for each parameter value to try
					msg = getNewMsg();
									
					if (log.isDebugEnabled()) {
						log.debug("Checking ["+msg.getRequestHeader().getMethod() + "] [" + msg.getRequestHeader().getURI() +"], parameter ["+ param + "] for Path Traversal (local file) with value ["+ prefix+target+"]");
					}
			        	        				        	
		            setParameter(msg, param, prefix + target);

		        	//send the modified request, and see what we get back
		        	sendAndReceive(msg);
		        	//does it match the pattern specified for that file name?
					String response = msg.getResponseHeader().toString() + msg.getResponseBody().toString();
		            matcher = Pattern.compile(LOCAL_FILE_TARGETS_AND_PATTERNS[i][1]).matcher(response);
		            //if the output matches, and we get a 200
		            if (matcher.find() && msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {
		                bingo(Alert.RISK_HIGH, Alert.WARNING, 
		                		null, param, 
		                		matcher.group(), null, msg);
		                // All done. No need to look for vulnerabilities on subsequent parameters on the same request (to reduce performance impact)
		                return; 
		            }
				}
	        }
	        //Check 2: try a local file Path Traversal on the file name of the URL (which obviously will not be in the target list above).
	        //first send a query for a random parameter value, and see if we get a 200 back
	        //if 200 is returned, abort this check (on the url filename itself), because it would be unreliable.
	        //if we know that a random query returns <> 200, then a 200 response likely means something!
	        //this logic is all about avoiding false positives, while still attempting to match on actual vulnerabilities
			msg = getNewMsg();
            setParameter(msg, param, NON_EXISTANT_FILENAME);
			//send the modified message (with a hopefully non-existent filename), and see what we get back
            sendAndReceive(msg);
            
            //do some pattern matching on the results.
            Pattern exceptionPattern = Pattern.compile("Exception");
            Matcher exceptionMatcher = exceptionPattern.matcher(msg.getResponseBody().toString());
            Pattern errorPattern = Pattern.compile("Error");
            Matcher errorMatcher = errorPattern.matcher(msg.getResponseBody().toString());
        	
            if ( msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK 
            			|| exceptionMatcher.find() 
            			|| errorMatcher.find() ) {
            	if (log.isDebugEnabled()) {
            		log.debug("It IS possible to check for local file Path Traversal on the url filename on ["+
            				msg.getRequestHeader().getMethod() + "] [" + msg.getRequestHeader().getURI() +"], ["+ param + "]");
            	}
            	String urlfilename = msg.getRequestHeader().getURI().getName();
            	
            	//for the url filename, try each of the prefixes in turn
            	for (int h=0; h < prefixCountOurUrl; h++) {
            		String prefixedUrlfilename = LOCAL_FILE_TARGET_PREFIXES[h]+urlfilename;
            		msg = getNewMsg();
		            setParameter(msg, param, prefixedUrlfilename);
					//send the modified message (with the url filename), and see what we get back
		            sendAndReceive(msg);
		            
		            //did we get an Exception or an Error?
		            exceptionMatcher = exceptionPattern.matcher(msg.getResponseBody().toString());
		            errorMatcher = errorPattern.matcher(msg.getResponseBody().toString());
		            
		            if ( msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK
		            		&& ( ! exceptionMatcher.find()) 
	            			&& ( ! errorMatcher.find())) {
						//if it returns OK, and the random string above did NOT return ok, then raise an alert
			            //since the filename has likely been picked up and used as a file name from the parameter
		                bingo(Alert.RISK_HIGH, Alert.WARNING, 
		                		null, param, prefixedUrlfilename, null, msg);
			            // All done. No need to look for vulnerabilities on subsequent parameters on the same request (to reduce performance impact)
			            return;  
		            }
            	}
            }
            
            
            //Check 3 for local file names
            //TODO: consider making this check 1, for performance reasons
	        //TODO: if the original query was http://www.example.com/a/b/c/d.jsp?param=paramvalue
	        //then check if the following gives comparable results to the original query
	        //http://www.example.com/a/b/c/d.jsp?param=../c/paramvalue
            //if it does, then we likely have a local file Path Traversal vulnerability
            //this is nice because it means we do not have to guess any file names, and would only require one
            //request to find the vulnerability 
            //but it would be foiled by simple input validation on "..", for instance.
            
    	}
		catch (Exception e) {
			log.error("Error scanning parameters for Path Traversal: "+ e.getMessage(), e);
			return;
		}
    }
    
	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

}
