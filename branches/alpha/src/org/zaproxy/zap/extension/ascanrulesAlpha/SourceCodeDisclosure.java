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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.ascanrulesAlpha.AscanUtils;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;
import org.zaproxy.zap.spider.URLCanonicalizer;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;

/**
 * a scanner that looks for application source code disclosure using path traversal techniques, SVN metadata/file disclosure, and Git metadata/file disclosure
 * 
 * @author 70pointer
 *
 */
public class SourceCodeDisclosure extends AbstractAppParamPlugin {
	
	static {
    	//register for internationalisation.  
		//this also needs to be done before the class is initialised, since the name of the scanner itself is i18ned
    	AscanUtils.registerI18N();	
	}

	//TODO: replace this with an actual random value, or someone will decide to play with our heads by creating actual files with this name.
    private static final String NON_EXISTANT_FILENAME = "thishouldnotexistandhopefullyitwillnot";
        
    //the prefixes to try for source file inclusion
    private String[] LOCAL_SOURCE_FILE_TARGET_PREFIXES = {
         ""
        ,"/"
        ,"../"
        ,"webapps/"  //in the case of servlet containers like Tomcat, JBoss (etc), sometimes the working directory is the application server folder
    	};
    
    //the prefixes to try for WAR/EAR file inclusion
    private String[] LOCAL_WAR_EAR_FILE_TARGET_PREFIXES = {

        	 "/../"			//for Tomcat, if the current directory is the tomcat/webapps/appname folder, when slashes ARE NOT added by the code (far less common in practice than I would have thought, given some real world vulnerable apps.)
        	,"../"			//for Tomcat, if the current directory is the tomcat/webapps/appname folder, when slashes ARE added by the code (far less common in practice than I would have thought, given some real world vulnerable apps.)
        	
        	,"/../../"		//for Tomcat, if the current directory is the tomcat/webapps/appname/a/ folder, when slashes ARE NOT added by the code
        	,"../../"		//for Tomcat, if the current directory is the tomcat/webapps/appname/a/ folder, when slashes ARE added by the code
        	
    		,"/../../../"	//for Tomcat, if the current directory is the tomcat/webapps/appname/a/b/ folder, when slashes ARE NOT added by the code
        	,"../../../"	//for Tomcat, if the current directory is the tomcat/webapps/appname/a/b/ folder, when slashes ARE added by the code

        	,"/../../../../"	//for Tomcat, if the current directory is the tomcat/webapps/appname/a/b/c/ folder, when slashes ARE NOT added by the code
        	,"../../../../"		//for Tomcat, if the current directory is the tomcat/webapps/appname/a/b/c/ folder, when slashes ARE added by the code
        	
        	,"/webapps/"	//for Tomcat, if the current directory is the tomcat folder, when slashes ARE NOT added by the code
        	,"webapps/"		//for Tomcat, if the current directory is the tomcat folder, when slashes ARE added by the code

        	,"/"			//for Tomcat, if the current directory is the tomcat/webapps folder, when slashes ARE NOT added by the code
        	,""				//for Tomcat, if the current directory is the tomcat/webapps folder, when slashes ARE added by the code
    	
        	,"/../webapps/"	//for Tomcat, if the current directory is the tomcat/temp folder, when slashes ARE NOT added by the code
        	,"../webapps/"	//for Tomcat, if the current directory is the tomcat/temp folder, when slashes ARE added by the code
    	};
    
    
    /**
     * details of the vulnerability which we are attempting to find 
     * (in this case 33 = "Path Traversal", 34 = "Predictable Resource Location")
     * 34 is the most correct, most of the time :/
     */
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_34");
    
    /**
     * the logger object
     */
    private static Logger log = Logger.getLogger(SourceCodeDisclosure.class);
    
    /**
     * Hirshberg class for longest common substring calculation.  
     * Damn you John McKenna and your dynamic programming techniques!
     */
    Hirshberg hirshberg = new Hirshberg ();
    
    /**
     * the threshold for whether 2 responses match. depends on the alert threshold set in the GUI. not final or static.
     */
    int thresholdPercentage = 0;
    
    /**
     * patterns expected in the output for common server side file extensions
     * TODO: add support for verification of other file types, once I get some real world test cases.
     */
    private static final Pattern PATTERN_JSP = Pattern.compile("<%.*%>");
    private static final Pattern PATTERN_PHP = Pattern.compile("<?php");
    private static final Pattern PATTERN_JAVA = Pattern.compile("class");  //Java is compiled, not interpreted, but this helps with my test cases.

    /**
     * returns the plugin id
     */
    @Override
    public int getId() {
        return 40;
    }

    /**
     * returns the name of the plugin
     */
    @Override
    public String getName() {
    	//this would return "Path Traversal", given WASC 33, but we want "Source Code Disclosure" (or an i18n equivalent)
        //if (vuln != null) {
        //    return vuln.getAlert();
        //}        
        return Constant.messages.getString("ascanalpha.sourcecodedisclosure.name");
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
        return Category.INFO_GATHER;
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
    	//DEBUG only
    	//log.setLevel(org.apache.log4j.Level.DEBUG);
    	
    	switch (this.getAlertThreshold()) {
    	case HIGH:
    		this.thresholdPercentage = 95;
    		break;
    	case MEDIUM:
    		this.thresholdPercentage = 75;
    		break;
    	case LOW:
    		this.thresholdPercentage = 50;
    		break;
    	case OFF:
    		this.thresholdPercentage = 50;	// == LOW
    		break;
    	case DEFAULT:
    		this.thresholdPercentage = 75; // == medium
    		break;
    	}
    }

	/**
     * scans the given parameter for source code disclosure vulnerabilities, using path traversal vulnerabilities
     */
    @Override
    public void scan(HttpMessage originalmsg, String paramname, String paramvalue) {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Attacking at Attack Strength: " + this.getAttackStrength());
                log.debug("Checking [" + getBaseMsg().getRequestHeader().getMethod() + "] ["
                        + getBaseMsg().getRequestHeader().getURI() + "], parameter [" + paramname + "], with original value ["+ paramvalue + "] for Source Code Disclosure");
            }
            
            //first send a query for a random parameter value
            //then try a query for the file paths and names that we are using to try to get out the source code for the current URL                        
            HttpMessage randomfileattackmsg = getNewMsg();
            setParameter(randomfileattackmsg, paramname, NON_EXISTANT_FILENAME);
            sendAndReceive(randomfileattackmsg);
            
            int originalversusrandommatchpercentage = calcMatchPercentage (originalmsg.getResponseBody().toString(), randomfileattackmsg.getResponseBody().toString());            
            if (originalversusrandommatchpercentage > this.thresholdPercentage) {
            	//the output for the "random" file does not sufficiently differ. bale out.
            	if (log.isDebugEnabled()) {
            		log.debug("The output for a non-existent filename ["+ NON_EXISTANT_FILENAME + "] does not sufficiently differ from that of the original parameter ["+ paramvalue+ "], at "+ originalversusrandommatchpercentage + "%, compared to a threshold of "+ this.thresholdPercentage + "%");
            	}
            	return;
            }
            
            if (this.isStop()) {
            	if (log.isDebugEnabled()) log.debug("Stopped, due to a user request");
            	return;
            }
                 
            //at this point, there was a sufficient difference between the random filename and the original parameter
            //so lets try the various path names that might point at the source code for this URL
            URI uri = originalmsg.getRequestHeader().getURI();
            String pathMinusLeadingSlash = uri.getPath().substring(1);
            String pathMinusApplicationContext = uri.getPath().substring( uri.getPath().indexOf("/", 1) + 1);
            
            //in the case of wavsep, should give us "wavsep"
            //use this later to build up "wavsep.war", and "wavsep.ear", for instance :)
            String applicationContext= uri.getPath().substring( 1, uri.getPath().indexOf("/", 1)); 
            
            //all of the sourceFileNames should *not* lead with a slash.
            String [] sourceFileNames = {uri.getName(), pathMinusLeadingSlash, pathMinusApplicationContext};
            
            //and get the file extension (in uppercase), so we can switch on it (if there was an extension, that is)
            String fileExtension = null;
            if(uri.getName().contains(".")) {
            	fileExtension = uri.getName().substring(uri.getName().lastIndexOf(".") + 1);
            	fileExtension = fileExtension.toUpperCase();
            }            

            //for each of the file names in turn, try it with each of the prefixes
            for (String sourcefilename : sourceFileNames) {
            	if (log.isDebugEnabled()) {
            		log.debug("Source file is ["+ sourcefilename + "]");
            	}
                //for the url filename, try each of the prefixes in turn
                for (int h = 0; h < LOCAL_SOURCE_FILE_TARGET_PREFIXES.length; h++) {
                	
                    String prefixedUrlfilename = LOCAL_SOURCE_FILE_TARGET_PREFIXES[h] + sourcefilename;
                    if (log.isDebugEnabled()) {                    	
                    	log.debug("Trying file name ["+ prefixedUrlfilename + "]");
                    }
                    
                    HttpMessage sourceattackmsg = getNewMsg();
                    setParameter(sourceattackmsg, paramname, prefixedUrlfilename);	                    
                    //send the modified message (with the url filename), and see what we get back
                    sendAndReceive(sourceattackmsg);
                    
                    int randomversussourcefilenamematchpercentage = calcMatchPercentage (
                    				randomfileattackmsg.getResponseBody().toString(), 
                    				sourceattackmsg.getResponseBody().toString());
                    if (randomversussourcefilenamematchpercentage  > this.thresholdPercentage) {
                    	//the output for the "source" file does not sufficiently differ from the random file name. bale out.
                    	if (log.isDebugEnabled()) {
                    		log.debug("The output for the source code filename ["+ prefixedUrlfilename + "] does not sufficiently differ from that of the random parameter, at "+ randomversussourcefilenamematchpercentage  + "%, compared to a threshold of "+ this.thresholdPercentage + "%");
                    	}
                    } else {
                    	//if we verified the response
                    	if (dataMatchesExtension (sourceattackmsg.getResponseBody().getBytes(), fileExtension)) {
                    		log.info("Source code disclosure!  The output for the source code filename ["+ prefixedUrlfilename + "] differs sufficiently from that of the random parameter, at "+ randomversussourcefilenamematchpercentage  + "%, compared to a threshold of "+ this.thresholdPercentage + "%");
                    		
		                    //if we get to here, is is very likely that we have source file inclusion attack. alert it.
		                    bingo(Alert.RISK_HIGH, Alert.WARNING,
		                    		Constant.messages.getString("ascanalpha.sourcecodedisclosure.name"),
		                    		Constant.messages.getString("ascanalpha.sourcecodedisclosure.desc"), 
		                    		getBaseMsg().getRequestHeader().getURI().getURI(),
		                            paramname, 
		                            prefixedUrlfilename,
		                            Constant.messages.getString("ascanalpha.sourcecodedisclosure.lfibased.extrainfo", prefixedUrlfilename, NON_EXISTANT_FILENAME, randomversussourcefilenamematchpercentage, this.thresholdPercentage),
		                            Constant.messages.getString("ascanalpha.sourcecodedisclosure.lfibased.soln"),
		                            Constant.messages.getString("ascanalpha.sourcecodedisclosure.lfibased.evidence"),
		                            sourceattackmsg
		                            );
		                    // All done on this parameter
		                    return;	
	                    } else {
	                    	if (log.isDebugEnabled()) {
	                    		log.debug("Could not verify that the HTML output is source code of type "+fileExtension + ". Next!");
	                    	}
	                    }
                    }
                if (this.isStop()) {
                	if (log.isDebugEnabled()) log.debug("Stopped, due to a user request");
                	return;
                    }
                }            
            }
            
            //if the above fails, get the entire WAR/EAR
            //but only if in HIGH or INSANE attack strength, since this generates more work and slows Zap down badly if it actually 
            //finds and returns the application WAR file!
            
            if ( this.getAttackStrength() == AttackStrength.INSANE ||
            		this.getAttackStrength() == AttackStrength.HIGH ) {
            		
	            //all of the warearFileNames should *not* lead with a slash.
            	//TODO: should we consider uppercase / lowercase on (real) OSs such as Linux that support such a thing?
            	//Note that each of these file types can contain the Java class files, which can be disassembled into the Java source code.
            	//this in fact is one of my favourite hacking techniques.
	            String [] warearFileNames = {applicationContext + ".war", applicationContext + ".ear", applicationContext + ".rar"};
	            
	            //for each of the EAR / file names in turn, try it with each of the prefixes
	            for (String sourcefilename : warearFileNames) {
	            	if (log.isDebugEnabled()) {
	            		log.debug("WAR/EAR file is ["+ sourcefilename + "]");
	            	}
	                //for the url filename, try each of the prefixes in turn
	                for (int h = 0; h < LOCAL_WAR_EAR_FILE_TARGET_PREFIXES.length; h++) {
	                	
	                    String prefixedUrlfilename = LOCAL_WAR_EAR_FILE_TARGET_PREFIXES[h] + sourcefilename;
	                    if (log.isDebugEnabled()) {
	                    	log.debug("Trying WAR/EAR file name ["+ prefixedUrlfilename + "]");
	                    }
	                    
	                    HttpMessage sourceattackmsg = getNewMsg();
	                    setParameter(sourceattackmsg, paramname, prefixedUrlfilename);	                    
	                    //send the modified message (with the url filename), and see what we get back
	                    sendAndReceive(sourceattackmsg);
	                    if (log.isDebugEnabled()) {
	                    	log.debug("Completed WAR/EAR file name ["+ prefixedUrlfilename + "]");
	                    }
	                    
	                    //since the WAR/EAR file may be large, and since the LCS does not work well with such large files, lets just look at the file size, 
	                    //compared to the original
	                    int randomversussourcefilenamematchpercentage = calcLengthMatchPercentage(sourceattackmsg.getResponseBody().length(), randomfileattackmsg.getResponseBody().length());
	                    if ( randomversussourcefilenamematchpercentage < this.thresholdPercentage ) {
	                    	log.info("Source code disclosure!  The output for the WAR/EAR filename ["+ prefixedUrlfilename + "] differs sufficiently (in length) from that of the random parameter, at "+ randomversussourcefilenamematchpercentage  + "%, compared to a threshold of "+ this.thresholdPercentage + "%");
	                    	
	                    	//Note: no verification of the file contents in this case.
	                    	
		                    //if we get to here, is is very likely that we have source file inclusion attack. alert it.
		                    bingo(Alert.RISK_HIGH, Alert.WARNING,
		                    		Constant.messages.getString("ascanalpha.sourcecodedisclosure.name"),
		                    		Constant.messages.getString("ascanalpha.sourcecodedisclosure.desc"), 
		                    		getBaseMsg().getRequestHeader().getURI().getURI(),
		                            paramname, 
		                            prefixedUrlfilename,
		                            Constant.messages.getString("ascanalpha.sourcecodedisclosure.lfibased.extrainfo", prefixedUrlfilename, NON_EXISTANT_FILENAME, randomversussourcefilenamematchpercentage, this.thresholdPercentage),
		                            Constant.messages.getString("ascanalpha.sourcecodedisclosure.lfibased.soln"),
		                            Constant.messages.getString("ascanalpha.sourcecodedisclosure.lfibased.evidence"),
		                            sourceattackmsg
		                            );
		                    
		                    // All done. No need to look for vulnerabilities on subsequent parameters on the same request (to reduce performance impact)
		                    return;	
	                    } else {
	                    	if (log.isDebugEnabled()) {
	                    		log.debug("The output for the WAR/EAR code filename ["+ prefixedUrlfilename + "] does not sufficiently differ in length from that of the random parameter, at "+ randomversussourcefilenamematchpercentage  + "%, compared to a threshold of "+ this.thresholdPercentage + "%");
	                    	}
	                    }
                    if (this.isStop()) {
                    	if (log.isDebugEnabled()) log.debug("Stopped, due to a user request");
                    	return;
	                    }
	                }
	            }
            } else {
            	if (log.isDebugEnabled()) {
            		log.debug("Not checking for EAR/WAR files for this request, since the Attack Strength is not HIGH or INSANE");
            	}
            }
            
            
        } catch (Exception e) {
            log.error("Error scanning parameters for Source Code Disclosure: " + e.getMessage(), e);
        }
    }

    @Override
    public void scan() {


        // and then scan the node itself (ie, at URL level, rather than at parameter level)
        if (log.isDebugEnabled()) {
			log.debug("Attacking at Attack Strength: " + this.getAttackStrength());
			log.debug("Checking [" + getBaseMsg().getRequestHeader().getMethod() + "] ["
					+ getBaseMsg().getRequestHeader().getURI() + "], for Source Code Disclosure (using SVN and Git meta-data)");
		}
        
        try {
        	URI uri = this.getBaseMsg().getRequestHeader().getURI();
			String filename = uri.getName();
			
			if ( filename != null && filename.length() > 0) {
				//there is a file name at the end of the path.
				
				//Look for SVN metadata that can be exploited to give us the source code.
				if ( findSourceCodeSVN (this.getBaseMsg())) {
					//found one. no need to try other methods, so bale out.
					return;
				}
				//Look for Git metadata that can be exploited to give us the source code.
				if ( findSourceCodeGit (this.getBaseMsg())) {
					//found one. no need to try other methods, so bale out.
					return;
				}

			} else {
				if (log.isDebugEnabled()) {
					log.debug ("The URI has no filename component, so there is not much point in looking for corresponding source code!");
				}
				//do not return, since we want to look for source code at the application level, as well as the file level
			}
		} catch (Exception e) {
			log.error("Error scanning a request for Source Code Disclosure: " + e.getMessage(), e);
		}
		
        // scan all of the individual parameters last 
        //(because this is definitely the slow way and less likely way of finding a vulnerability like this)
        //Note: we will only do this if none of the methods above find a source code disclosure.
    	// ie calls scan (a, b, c)
        super.scan();

    }


	/**
     * returns whether the message response content matches the specified extension
     * @param svnsourcefileattackmsg
     * @param fileExtension
     * @return
     */
    private boolean dataMatchesExtension(byte [] data, String fileExtension) {
    	if ( fileExtension != null) {
    		if (fileExtension.equals ("JSP")) {
    			if ( PATTERN_JSP.matcher(new String(data)).find() ) return true; 
    		} else if (fileExtension.equals ("PHP")) {
    			if ( PATTERN_PHP.matcher(new String(data)).find() ) return true; 	
    		} else if (fileExtension.equals ("JAVA")) {
    			if ( PATTERN_JAVA.matcher(new String(data)).find() ) return true; 
    			
    		} else {
    			if (log.isDebugEnabled()) {
    				log.debug ("Unknown file extension "+ fileExtension + ". Accepting this file type without verifying it. Could therefore be a false positive.");
    			}
    			//unknown file extension. just accept it as it is.
    			return true;
    		}
    		//known file type, but not matched. do not accept it.
    		return false;
    	} else {
			//no file extension, therefore no way to verify the source code.. so accept it as it is
			return true;
		}
	}

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH; //definitely a High. If we get the source, we don't need to hack the app any more, because we can just analyse it off-line! Sweet..
    }

    @Override
    public int getCweId() {
        return 541;  //Information Exposure Through Include Source Code
    }

    @Override
    public int getWascId() {
    	//this is not entirely satisfactory. 
    	//the vulnerability could be caused by either "Path Traversal" (33), 
    	//or by "Predictable Resource Location" (34)
    	//but we need to choose just one, so "Predictable Resource Location" is probably the most correct general response to give
        return 34;  //Predictable Resource Location
    }
    
	/**
	 * calculate the percentage length of similarity between 2 strings.
	 * TODO: this method is also in LDAPInjection. consider re-factoring out this class up the hierarchy, or into a helper class.
	 * @param a 
	 * @param b
	 * @return
	 */
	private int calcMatchPercentage (String a, String b) {
		if (log.isDebugEnabled()) {
			log.debug("About to get LCS for [" + a +"] and [ "+ b + "]");
		}
		if ( a == null && b == null )
			return 100;
		if ( a == null || b == null )
			return 0;
		if ( a.length() == 0 && b.length() == 0)
			return 100;
		if ( a.length() == 0 || b.length() == 0)
			return 0;
		String lcs = hirshberg.lcs(a, b);
		if (log.isDebugEnabled()) {
			log.debug("Got LCS: "+ lcs);
		}
		//get the percentage match against the longer of the 2 strings
		return (int) ( ( ((double)lcs.length()) / Math.max (a.length(), b.length())) * 100) ;
		
	}
	/**
	 * calculate the percentage length between the 2 strings.
	 * @param a
	 * @param b
	 * @return
	 */
	private int calcLengthMatchPercentage (int a, int b) {
		if ( a == 0 && b == 0 )
			return 100;
		if ( a == 0 || b == 0 )
			return 0;
		
		return (int) ( ( ((double)Math.min (a, b)) / Math.max (a, b)) * 100) ;
		
	}
	
    /**
     * finds the source code for the given file, using Git metadata on the server (if this is available)
     * @param uri the URI of a file, whose source code we want to find
     * @return Did we find the source code?
     */
    private boolean findSourceCodeGit(HttpMessage originalMessage) throws Exception {
    	byte [] disclosedData = {};
		String gitsha1 = null;
		String gitindexpath = null;
		try {
	    	URI originalURI = originalMessage.getRequestHeader().getURI();
	    	String originalURIWithoutQuery = originalURI.getScheme() + "://" + originalURI.getAuthority() + originalURI.getPath(); 
	    	String canonicalisedOriginalURIStringWithoutQuery = URLCanonicalizer.getCanonicalURL(originalURIWithoutQuery);
	    	String path = originalURI.getPath();
			if (path == null) path="";
			String filename = originalURI.getName();		
	
			String fileExtension = null;
			if(filename.contains(".")) {
				fileExtension = filename.substring(filename.lastIndexOf(".") + 1);
				fileExtension = fileExtension.toUpperCase();
			}
			
			GitMetadata git = new GitMetadata (4096);
			
			//look for the .git/index file in the directory and parent directories of the file for
			//which we are attempting to get the source code. 
			String modifiedpath = path;				
			byte [] data =  {};
			boolean gitSHA1located = false;
			//work backwards from the original path, stripping off one folder at a time
			//until we find a valid Git index file that contains our file name!
			modifiedpath = modifiedpath.substring( 0, modifiedpath.lastIndexOf("/")); 
			while ((! modifiedpath.equals("")) && (! gitSHA1located)) {
				gitindexpath = modifiedpath + "/.git/index";
				String gitbasepath= modifiedpath + "/.git/";
									
    			URI gitindexuri = new URI (originalURI.getScheme(), originalURI.getAuthority(), gitindexpath, null, null);
				try {
					if (log.isDebugEnabled()) log.debug("Trying for a Git index file "+ gitindexuri.getURI());
	    			data = git.getURIResponseBody (gitindexuri, false);
					//get the list of relative file paths and Git SHA1s from the file 
					Map <String, String> gitFiles = git.getIndexSha1s (data);
					if ( gitFiles != null) {
						if (log.isDebugEnabled()) log.debug("We found a Git index file at '"+ gitindexpath + "'");
						
						//now make sure it contains the file we're looking for.. maybe it does not..
						Set<Entry<String, String>> entrySet = gitFiles.entrySet();
						Iterator<Entry<String, String>> entryIterator = entrySet.iterator();							
						while (entryIterator.hasNext()) {
							Entry<String, String> gitIndexEntry = entryIterator.next();
							
							//do a canonicalized comaprison (the Git index entry has the form "blah/.git/../something.txt", which does not match "blah/something.txt"
							//unless the 2 are canonicalised
							//the URIs from the Git index do not have a query or fragment component, so no need to strip those off here
							String canonicalisedGitEntryURIstring = URLCanonicalizer.getCanonicalURL(new URI (originalURI.getScheme(), originalURI.getAuthority(), gitbasepath + gitIndexEntry.getKey(), null, null).getURI());
							if (canonicalisedGitEntryURIstring.equals(canonicalisedOriginalURIStringWithoutQuery)) {
								gitsha1= gitIndexEntry.getValue();
								if (log.isDebugEnabled()) log.debug("We found our file in the Git index '"+ gitindexpath + "'. The Git SHA1 is "+ gitsha1);
								
								//no need to keep on looping if we found our entry
								//note: gitindexpath is set above, so no need to set it here.
								gitSHA1located=true;
								break;
							}
							else {
								if (log.isDebugEnabled()) log.debug("Git index file entry '"+ canonicalisedGitEntryURIstring  + "' does not match '"+ canonicalisedOriginalURIStringWithoutQuery+ "'");
							}
						}
					} else {							
						continue;  //to the next iteration, Batman.
						}
					}
				catch (Exception e) {
					if (log.isDebugEnabled()) log.debug("Ignoring an error getting/parsing '"+ gitindexpath + "', while trying to find the Git SHA1 value for '"+ path + "'");
				}
				finally {
					//move to the next parent directory
					modifiedpath = modifiedpath.substring( 0, modifiedpath.lastIndexOf("/"));
				}
				
				if (isStop()) {
					if (log.isDebugEnabled()) log.debug("Stopped scanner (while trying to find the Git index file), due to a user request");
					return false;
				}
			}
			
			//do we have a shot at getting the source code using Git?
			if ( gitsha1 == null || gitsha1.equals("") || gitindexpath == null || gitindexpath.equals("")) {
				if (log.isDebugEnabled() ) log.debug ("A Git SHA1 value or Git index path for '"+ path +"' was not found.");
				return false;
			}			
	    	if ( ! git.validateSHA1(gitsha1)) {
				if (log.isDebugEnabled() ) log.debug ("The 'gitsha1' parameter '"+ gitsha1+ "' does not appear to be a valid format for a Git SHA1 value");
				return false;
			}
			String gitbasepath = git.getBaseFolder (gitindexpath);
			if (gitbasepath == null || gitbasepath.equals("")) {
				if (log.isDebugEnabled() ) log.debug ("The 'gitindexpath' parameter '"+ gitbasepath + "' does not appear to be valid.");
				return false;
			}
			//get the data from Git, using its SHA1 value.
			disclosedData = git.getBlobData (this.getBaseMsg(), gitbasepath, gitsha1);  //look for data for the file's Git SHA1, and inflate it
			String [] gitURIs = git.getGitURIs();
			
			//so we have the data from Git for the sha1/file in questions.. does it match the original data?
			//if not (but if it still looks valid), then throw a "source code disclosure" alert			
			if (! Arrays.equals(disclosedData, originalMessage.getResponseBody().getBytes())) {
				
				//check the contents of the output to some degree, if we have a file extension.
				//if not, just try it (could be a false positive, but hey)    			
				if (dataMatchesExtension (disclosedData, fileExtension)) {
					log.info("Source code disclosure, using Git metadata leakage!");

					//source file inclusion attack. alert it.
					//Note that, unlike with SVN, the Git data is extracted not from one file, but by parsing a series of files.
					//we cannot meaningfully raise an alert on any one file, except perhaps the file on which the attack was launched.
					//it's the least worst way of doing it, IMHO.
					bingo(	Alert.RISK_HIGH, 
							Alert.WARNING,
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.name"),
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.desc"), 
							getBaseMsg().getRequestHeader().getURI().getURI(),
							null, //parameter being attacked: none.
							null,  //attack
							new String (disclosedData), 	//Constant.messages.getString("ascanalpha.sourcecodedisclosure.gitbased.extrainfo", filename, StringUtils.join(gitURIs,", ")),  	//extraInfo
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.gitbased.soln"),
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.gitbased.evidence", filename, StringUtils.join(gitURIs,", ")),
							originalMessage
							);					
					return true;
					}
				//does not match the extension
				return false;
				} 
			else {
				if (log.isDebugEnabled()) log.debug("The data disclosed via Git meta-data is not source code, since it matches the data served when we requested the file in the normal manner (source code is not served by web apps, and if it is, then you have bigger problems)");
				return false;
				}
			}
		catch (FileNotFoundException e) {
			if (log.isDebugEnabled()) log.debug("Data could not be read for SHA1 '"+ gitsha1 + "'");
			return false;
			}
		catch (Exception e) {
			log.error("Some other error occurred when reading data for Git SHA1 '"+ gitsha1 + "': "+ e.getMessage());
			return false;
			}
	}
    
    /**
     * finds the source code for the given file, using SVN metadata on the server (if this is available)
     * @param uri the URI of a file, whose source code we want to find
     * @return Did we find the source code?
     */
    private boolean findSourceCodeSVN(HttpMessage originalMessage) throws Exception {
    	
    	URI uri = originalMessage.getRequestHeader().getURI();
		String path = uri.getPath();
		if (path == null) path="";
		//String filename = path.substring( path.lastIndexOf('/')+1, path.length() );
		String filename = uri.getName();

		String fileExtension = null;
		if(filename.contains(".")) {
			fileExtension = filename.substring(filename.lastIndexOf(".") + 1);
			fileExtension = fileExtension.toUpperCase();
		}

		//Look for SVN metadata containing source code
		String pathminusfilename = path.substring( 0, path.lastIndexOf(filename));

		HttpMessage svnsourcefileattackmsg = new HttpMessage(new URI (uri.getScheme(), uri.getAuthority(), pathminusfilename + ".svn/text-base/" + filename + ".svn-base", null, null));
		svnsourcefileattackmsg.setCookieParams(this.getBaseMsg().getCookieParams());
		//svnsourcefileattackmsg.setRequestHeader(this.getBaseMsg().getRequestHeader());
		sendAndReceive(svnsourcefileattackmsg);
		
		//if we got a 404 specifically, then this is NOT a match
		//note that since we are simply relying on the file existing or not, we 
		//will not attempt any fuzzy matching. Old school.
		//this check is necessary, otherwise a recursive scan on nodes in the url path cause lots of false positives.
		if ( svnsourcefileattackmsg.getResponseHeader().getStatusCode() !=  HttpStatusCode.NOT_FOUND ) {
			
			if (! Arrays.equals(svnsourcefileattackmsg.getResponseBody().getBytes(), originalMessage.getResponseBody().getBytes())) {
				
				String attackFilename = uri.getScheme() + "://" + uri.getAuthority() + pathminusfilename + ".svn/text-base/" + filename + ".svn-base";
	
				//check the contents of the output to some degree, if we have a file extension.
				//if not, just try it (could be a false positive, but hey)    			
				if (dataMatchesExtension (svnsourcefileattackmsg.getResponseBody().getBytes(), fileExtension)) {
					log.info("Source code disclosure, using SVN metadata leakage!");
	
					//if we get to here, is is very likely that we have source file inclusion attack. alert it.
					bingo(Alert.RISK_HIGH, Alert.WARNING,
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.name"),
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.desc"), 
							getBaseMsg().getRequestHeader().getURI().getURI(),
							null, 
							attackFilename,
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.svnbased.extrainfo", filename, attackFilename),
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.svnbased.soln"),
							Constant.messages.getString("ascanalpha.sourcecodedisclosure.svnbased.evidence"),
							svnsourcefileattackmsg
							);
					//if we found one, do not even try the "super" method, which tries each of the parameters,
					//since this is slow, and we already found an instance
					return true;
				} else {
					if (log.isDebugEnabled())  log.debug("The HTML output does not look like source code of type "+fileExtension );					
				}
			} else {
				if (log.isDebugEnabled()) log.debug("The data disclosed via SVN meta-data is not source code, since it matches the data served when we requested the file in the normal manner (source code is not served by web apps, and if it is, then you have bigger problems)");
				return false;
			}
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Got a 404, so the SVN source code file was not found");
			}
		}
    return false;	
    }


    /**
     * parse Git metadata to the degree necessary to extract source code from it 
     * @author 70pointer@gmail.com
     *
     */
    public class GitMetadata {
    	/**
    	 * a pattern used to determine if a given SHA1 value is valid (from the point of view of the format of the value)  
    	 */
    	final Pattern sha1pattern = Pattern.compile ("[0-9a-f]{20}");

    	/**
    	 * a pattern used to determine the base folder for a Git file (ie, the ".git" folder path)
    	 */

    	final Pattern basefolderpattern = Pattern.compile("^(.*/.git/)[^/]*$");

    	/**
    	 * the object used to send additional requests
    	 */
    	//HttpSender httpSender;

    	/**
    	 * the size of buffer to use when inflating deflated Git data
    	 */
    	private int inflateBufferSize;
    	
    	/**
    	 * store off the URIs that were requested to get the source code disclosure
    	 * The current logic uses a maximum of 5 (worst case): 
    	 * 	.git/index												- the list of files in the repo
    	 *  .git/objects/49/a7eca74dfebcaba00ea5eee60dcff7918f930c  - an example unpacked (aka "loose") file in the objects directory
    	 *  .git/objects/info/packs									- contains the name of the pack file and index file 
    	 *  .git/objects/pack/pack-ae0d45afdff3d83a8b724294aa33e617c5e3dce9.idx		- an example pack index file 
    	 *  .git/objects/pack/pack-ae0d45afdff3d83a8b724294aa33e617c5e3dce9.pack	- an example pack data file
    	 */
    	private String uris [] = new String [5];
    	
    	/**
    	 * how many URIs have we recorded so far?
    	 */
    	private int uriCount = 0;
    	


    	public GitMetadata(int inflateBufferSize) {
    		this.inflateBufferSize = inflateBufferSize;
    	}
    	
    	/**
    	 * gets the (minimal) array of Git URIs that were queried
    	 * @return
    	 */
    	public String [] getGitURIs () {
    		String [] temp = new String [uriCount]; 
    		for (int i=0; i< uriCount; i++) {
    			temp[i]=uris[i];
    		}
    		return temp;
    	}

    	/**
    	 * inflate the byte array, using the specified buffer size
    	 * @param data the data to inflate
    	 * @param buffersize the buffer size to use when inflating the data
    	 * @return the inflated data 
    	 * @throws Exception
    	 */
    	protected byte[] inflate (byte[] data, int buffersize) throws Exception { 
    		Inflater inflater = new Inflater();  
    		inflater.setInput(data); 

    		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length); 
    		byte[] buffer = new byte[buffersize]; 
    		while (!inflater.finished()) { 
    			int count = inflater.inflate(buffer); 
    			outputStream.write(buffer, 0, count); 
    		} 
    		outputStream.close(); 
    		inflater.end();
    		return outputStream.toByteArray(); 
    	} 

    	/**
    	 * get the URL contents, from a local cache, if possible. Only a HTTP 200 error code is considered a success. Redirects are not automatically followed. 
    	 * @param url  the URL to request
    	 * @param inflate whether to interpret the results as deflated, and inflate them
    	 * @return the URI contents, inflated, if requested. If the HTTP response code != 200, returns NULL 
    	 * @throws Exception
    	 */
    	protected byte [] getURIResponseBody (URI uri, boolean inflate) throws Exception {
    		byte [] data = null;
    		if (log.isDebugEnabled()) log.debug("Debug: Requesting URI '"+ uri + "'");

    		//record the URI as it is queried
    		this.uris[uriCount++] = uri.getURI();

			HttpMessage msg = new HttpMessage(uri);
			sendAndReceive (msg);
			if  (msg.getResponseHeader().getStatusCode() != HttpStatus.SC_OK) {
				throw new FileNotFoundException(uri.getURI());
			}
			data = msg.getResponseBody().getBytes();
    		
    		if (inflate) {
    			return inflate (data, inflateBufferSize);
    		} else 
    			return data;		
    	}

    	/**
    	 * get data for a given SHA1 blob, trying both the unpacked (loose) and packed formats
    	 * @param basemsg the base message to use when retrieving additional resources   
    	 * @param gitbasepath the Git base path 
    	 * @param filesha1 the SHA1 associated with the file in Git 
    	 * @return the binary data associated with the file in Git, as specified by the filesha1 parameter 
    	 * @throws Exception
    	 */
    	public byte [] getBlobData (HttpMessage basemsg, String gitbasepath, String filesha1) throws Exception {
    		//try the unpacked first, cos it's simpler and quicker. (It might not be the common case, however)
    		//but if that fails, try to get the data from the packed files.
    		try {
    			return getBlobData (basemsg, gitbasepath, filesha1, false);
    		}
    		catch (FileNotFoundException e) {
    			//try the packed format instead
    			if (log.isDebugEnabled()) log.debug("An unpacked file was not found for SHA1 "+ filesha1 + ". Trying for a packed file instead");
    			
    			//and re-initialise the URIs that we record, because the file in unpacked format did not work out for us 
    			this.uriCount=0;
    			return getBlobData (basemsg, gitbasepath, filesha1, true);
    		}
    	}

    	/**
    	 * get data for a given SHA1 blob, using either the loose or packed formats
    	 * @param basemsg the base message to use when retrieving additional resources
    	 * @param gitbasepath the Git base path
    	 * @param filesha1 the SHA1 associated with the file in Git
    	 * @param trypacked try the packed format, or try the loose format
    	 * @return the binary data associated with the file in Git, as specified by the filesha1 parameter
    	 * @throws Exception
    	 */
    	public byte [] getBlobData (HttpMessage basemsg, String gitbasepath, String filesha1, boolean trypacked) throws Exception {

    		URI originaluri = basemsg.getRequestHeader().getURI();
    		if (! trypacked) {
    			//try the unpacked (loose) format		 
    			URI gitobjecturi = new URI (originaluri.getScheme(), originaluri.getAuthority(), gitbasepath + "objects/" + filesha1.substring(0,2) + "/" + filesha1.substring(2), null, null);

    			if (log.isDebugEnabled()) log.debug("The internal Git (loose) file name is "+ gitobjecturi.getURI());
    			byte [] data = getURIResponseBody (gitobjecturi, true);
    			
    			ByteBuffer dataBuffer = ByteBuffer.wrap(data);
    			StringBuilder sb= new StringBuilder ();
    			while (true) {
    				byte b = dataBuffer.get();
    				if ( b == ' ') break;
    				sb.append((char)b);
    			}
    			String objecttype = new String (sb);
    			if (! objecttype.equals ("blob")) {
    				throw new Exception ("The Git 'loose' file '"+ gitobjecturi + "' is not of type 'blob': '" + objecttype + "'");
    			}			
    			//read the size of data in the file (which appears as ASCII digits in the text), until we get a 0x00
    			sb= new StringBuilder ();
    			while (true) {
    				byte b = dataBuffer.get();
    				if ( b == 0x00) break;
    				sb.append((char)b);
    			}
    			int dataSize = Integer.parseInt(new String(sb));
    			
    			//now read that number of bytes from the bytebuffer, or at least attempt to.. 
    			byte [] blobDecoded = new byte [dataSize];
    			dataBuffer.get (blobDecoded);
    			//that's it. we're done. return the decoded data, which will hopefully be source code :) 
    			return blobDecoded;
    		} 
    		else {
    			//try the packed format
    			
    			//With the Git "packed" format, there are Git "pack index" files, and Git "pack" files. They come as a set. You need both to get the contents of the file you're looking for.
    			//The name of the Git "pack" files and "pack index" files is based on the SHA1 sum of the SHA1 objects that it contains, and is not guessable.  
    			//This is an issue if you do not already know what pack files live in the directory (unless you have a directory listing, for instance).
    			//Luckily, in practice, in most cases (although not always) the name of the "pack" file is contained in an ".git/objects/info/packs" file in the Git repo metadata. 
    			//The ".git/objects/info/packs" can also contain the names of multiple pack files, which I have not seen in practice. That scenario is not currently supported here.
    			
    			//Both the "pack" and "pack index" files have an associated version number, but not necessarily the same version number as each other. 
    			//There are constraints and interdependencies on these version numbers, however. 
    			
    			//The Git "pack index" file currently comes in versions 1,2, and 3 (as of January 30, 2014).
    			    			
    			//version 1 "pack index" files are not seen in the wild, but can be created using later versions of Git, if necessary.  Version 1 is supported here. 
    			//				(Version 1 "pack index" files are seen in conjunction with Version 2 "pack" files, but there is no reason (that I know of) why they should not also support Version 3 or 4 pack files).
    			//version 2 "pack index" files use either a version 2 or version 3 "pack" file. All these versions are supported here.
    			//    			(Version 1 and 2 "pack index" file formats have structural differences, but not not wildly dis-similar).
    			//version 3 "pack index" file cannot yet be created by any currently known version of Git, but the format is documented.  
    			//				(Version 3 "pack index" files require a version 4 "pack file". Both these versions are tentatively supported here, although this code has never been tested)
    			
    			//The Git "pack" file currently comes in versions 1,2,3, and 4 (as of January 30, 2014).
    			//Version 1 "pack" files do not appear to be documented. They are not supported here. 
    			//Version 2 "pack files" are used with version 2 "pack index" files. This is a common scenario in the wild. Both versions are supported here. 
    			//Version 3 "pack files" are (also) used with version 2 "pack index" files. Both versions are supported here.
    			//           (Version 3 "pack files" are identical in format to version 2, with only the version number differing)
    			//Version 4 "pack files" are used in conjunction with version 3 "pack index" files. Both these versions are tentatively supported here, although this code has never been tested.
    			
    			//There are also separate version numbers in the Git "index file" (unrelated to the "pack index" files mentioned above), which are probably similarly inter-related.
    			//I do not have a mapping of the Git version number (1.7.6 / 1.8.5, for instance) to any of the the internal file version numbers that they create (by default) or support. So sue me.

    			URI uri = new URI (originaluri.getScheme(), originaluri.getAuthority(), gitbasepath + "objects/info/packs", null, null);

    			if (log.isDebugEnabled()) log.debug("The internal Git file containing the name of the pack file is "+ uri);

    			byte [] packinfofiledata = null;
    			try {
    				packinfofiledata = getURIResponseBody (uri, false);
    			}
    			catch (FileNotFoundException e) {
    				log.error("We could not read '"+ uri + "' to get the name of the pack file containing the content: "+ e.getMessage());
    				throw e;
    			}
    			ByteBuffer dataBuffer = ByteBuffer.wrap(packinfofiledata);
    			StringBuilder sb= new StringBuilder ();
    			while (true) {
    				byte b = dataBuffer.get();
    				if ( b == ' ') break;
    				sb.append((char)b);
    			}
    			String objecttype = new String (sb);
    			if (! objecttype.equals ("P")) {
    				throw new Exception ("The pack info file is not of type 'P': '" + objecttype + "'");
    			}

    			//the file should  begin with "P ", and everything after that is the pack file name (and exclude the 2 trailing newlines as well)
    			//TODO: handle the case where this file contains the name of multiple pack files. Currently, i have no test cases. Maybe in extremely large Git repositories?
    			byte [] packfilenamebytes = new byte [packinfofiledata.length - 4];  
    			dataBuffer.get(packfilenamebytes);
    			String packfilename = new String (packfilenamebytes);
    			//validate that the file name looks like "pack*.pack"
    			Matcher packfilenamematcher = Pattern.compile("^pack-[0-9a-f]{40}\\.pack$").matcher(packfilename);
    			if  (! packfilenamematcher.find()) {
    				throw new Exception ("The pack file name '"+packfilename+"' does not match the expected pattern");
    			}

    			//Now generate the full name of the pack file, and the pack index.
    			URI packuri = new URI (originaluri.getScheme(), originaluri.getAuthority(), gitbasepath + "objects/pack/" + packfilename, null, null);
    			URI packindexuri = new URI (originaluri.getScheme(), originaluri.getAuthority(), gitbasepath + "objects/pack/" + packfilename.substring (0, packfilename.length() - 5) + ".idx", null, null);

    			//retrieve the content for the "pack index" file!
    			byte [] packfileindexdata = null;
    			try {
    				packfileindexdata = getURIResponseBody (packindexuri, false);
    			}
    			catch (FileNotFoundException e) {
    				System.out.println("We could not read '"+ packindexuri + "', which is necessary to get the packed contents of the SHA1 requested: "+ e.getMessage());
    				throw e;
    			}

    			//retrieve the content for the "pack" file!
    			byte [] packfiledata = null;
    			try {
    				packfiledata = getURIResponseBody (packuri, false);
    			}
    			catch (FileNotFoundException e) {
    				System.out.println("We could not read '"+ packuri + "', which should contain the packed contents of the SHA1 requested: "+ e.getMessage());
    				throw e;
    			}

    			//now that we know we have both the "pack index" and the "pack" (data) file, parse the data
    			//first parse out some signature data info from the "pack" file
    			ByteBuffer packfileheaderBuffer = ByteBuffer.wrap(packfiledata, 0, 12);
    			byte [] packfileheaderSignatureArray = new byte [4];  //4 bytes
    			packfileheaderBuffer.get(packfileheaderSignatureArray);
    			if (! new String(packfileheaderSignatureArray).equals("PACK")) {
    				throw new Exception ("The pack file header does not appear to be valid");
    			}
    			int packFileVersion = packfileheaderBuffer.getInt(); //4 bytes 
    			int packEntryCount = packfileheaderBuffer.getInt();  //4 bytes

    			if ( packFileVersion != 2 && packFileVersion != 3 && packFileVersion != 4) {
    				throw new Exception ("Only Git Pack File versions 2, 3, and 4 are currently supported. Git Pack File Version "+ packFileVersion + " was found. Contact the zaproxy (OWASP Zap) dev team");
    			}
    			
    			//for pack file version 4, read the SHA1 tables from the "pack" file at this point
    			//these used to live in the "pack index" file, in earlier versions.
    			//Note: since at this point in time, there is no way to generate a v3 pack index file + v4 pack file
    			//so this particular block of code remains hypothetical.  it seems to comply with the documented version 4 "pack" file format, however, and it 
    			//works for version 2 "pack index" and version 2 "pack" files, which appears to be the most common combination seen in the wild.
    			
    			int sha1Index = Integer.MAX_VALUE;
    			int packEntryOffsetArray [] = null;
    			int packEntryOffsetArrayOrdered[] = null;
    			int indexEntryCount = 0;
    			
    			if ( packFileVersion >= 4 ) {
					sha1Index = Integer.MAX_VALUE;
					//the tables in the V4 tables in the pack file are variable length, so just grab the data after the main header for now
					ByteBuffer packfileTablesBuffer = ByteBuffer.wrap(packfiledata, 12, packfiledata.length - 12);
    				//read the series of 20 byte sha1 entries.
    				//ours *should* be in here somewhere.. find it
    				//make sure to read *all* of the entries from the file (or else seek to the end of the data), so the parsing logic is not broken.
    				//TODO: use a binary search to find this in a more efficient manner
    				
    				for (int i=0; i< packEntryCount; i++) {
    					byte [] packTableData = new byte [20];
    					packfileTablesBuffer.get(packTableData);
    					String packTableSha1 = Hex.encodeHexString( packTableData );
    					//TODO :use more efficient byte based comparison to find the SHA1 here (and in similar code in pack index version 2 logic, later..
    					if ( packTableSha1.equals(filesha1) ) {
    						if (log.isDebugEnabled()) log.debug("FOUND our SHA1 "+ packTableSha1+ " at entry " + i + " in the v4 pack tables");
    						sha1Index=i;
    						
    						//we do not need to "read past" all the entries.
    						break;
    					}
    				}
    			}
    			
    			//try to parse the "pack index" as a version 1 "pack index" file, which has a different layout to subsequent versions.
    			//use a separate ByteBuffer for this, in case things don't work out (becuase they probably will not work out) :)
    			try {
	    			ByteBuffer packindexfileV1dataBuffer = ByteBuffer.wrap(packfileindexdata);
	    			byte packEntrySizeArray [] = new byte [256*4];
					packindexfileV1dataBuffer.get(packEntrySizeArray);
					
					if ( /*packEntrySizeArray[0]== 0xFF && */
							packEntrySizeArray[1]== 't' &&
							packEntrySizeArray[2]== 'O' && 
							packEntrySizeArray[3]== 'c') {
						//the signature is a non-V1 signature.  
						throw new NotV1PackIndexFileException ();
						}
					//get the last 4 bytes as an int, network order.
					indexEntryCount  = ( packEntrySizeArray[(255*4)+3] << 0);  
					indexEntryCount |= ( packEntrySizeArray[(255*4)+2] << 8);
					indexEntryCount |= ( packEntrySizeArray[(255*4)+1] << 16);
					indexEntryCount |= ( packEntrySizeArray[(255*4)+0] << 24);
					
					//validate that this matches the number of entries in the "pack" file.
					if ( indexEntryCount != packEntryCount ) {
						throw new Exception ("The entry count ("+ indexEntryCount + ") from the version 1 pack index file does not match the entry count (" + packEntryCount + ") from the pack file ");
					}
					if (log.isDebugEnabled()) log.debug("Got a pack index entry count of "+ indexEntryCount + " from the version 1 pack index file");
					
					//read the indexEntryCount * (4+20) byte entries (4 + 20 blackbirds baked in a pie!)
					sha1Index = Integer.MAX_VALUE;
					packEntryOffsetArray = new int [indexEntryCount];
					packEntryOffsetArrayOrdered = new int [indexEntryCount];
					
    				//TODO: use a binary search to find this in a more efficient manner
    				for (int i=0; i< indexEntryCount; i++) {    					
    					//read 4 bytes offset (the offset of the SHA1's data in the "pack" file)
    					packEntryOffsetArray[i]=packindexfileV1dataBuffer.getInt();
						packEntryOffsetArrayOrdered[i]=packEntryOffsetArray[i];
    					
						//read 20 bytes SHA1
    					byte [] indexEntryIdBuffer = new byte [20];
    					packindexfileV1dataBuffer.get(indexEntryIdBuffer);
    					String indexEntrySha1 = Hex.encodeHexString( indexEntryIdBuffer );
    					if ( indexEntrySha1.equals(filesha1) ) {
    						if (log.isDebugEnabled()) log.debug("FOUND our SHA1 "+ indexEntrySha1+ " at entry " + i + " in the SHA1 table");
    						sha1Index=i;
    					}
    				}
    				//final sanity check, if all of the above panned out for version 1 index file.
    				//Note: we *think* that that "pack index" file version 1 is compatible with "pack" file version 3 and 4, but really, we don't know for sure.. Again, so sue me. 
    				int packindexFileVersion = 1;
    				if (packFileVersion!= 2 && packFileVersion!= 3 && packFileVersion!= 4) {
						throw new Exception ("Pack index file version ("+ packindexFileVersion + ") is incompatible with pack file version (" + packFileVersion + ")");
					}
    				
				}
    			catch (NotV1PackIndexFileException e) {
    				//so it's not a version 1 "pack index" file. Try parsing it as a version 2, 3, 4 (or later versions, once there are more versions, and we support them) 
    				if (log.isDebugEnabled()) log.debug("The 'pack index' file looks like a > version 1 'pack index' file. Trying to parse it as later formats instead");
    			
	    			//Parse the "pack index" file header				
					ByteBuffer packindexfiledataBuffer = ByteBuffer.wrap(packfileindexdata);
					
					byte [] packindexfileheaderSignatureArray = new byte [4];
					packindexfiledataBuffer.get(packindexfileheaderSignatureArray);
					if ( 	
							/*packindexfileheaderSignatureArray[0]!= 0xFF || */
							packindexfileheaderSignatureArray[1]!= 't' ||
							packindexfileheaderSignatureArray[2]!= 'O' || 
							packindexfileheaderSignatureArray[3]!= 'c') {
						throw new Exception ("The pack index file header does not appear to be valid for pack index file version 2, 3, or 4: '"+ new String (packindexfileheaderSignatureArray)+ "' was found" );
					}
	
					//Note: version 1 is hanled separately, so need to check for it here.
					int packindexFileVersion = packindexfiledataBuffer.getInt();
					if (packindexFileVersion !=2 && packindexFileVersion != 3 ) {   				
						throw new Exception ("Pack index file version("+ packindexFileVersion + ") is not supported");
					}
					if ((packFileVersion ==2 || packFileVersion ==3) && packindexFileVersion!= 2) {
						throw new Exception ("Pack index file version ("+ packindexFileVersion + ") is incompatible with pack file version (" + packFileVersion + ")");
					}
					if (packindexFileVersion == 3 && packFileVersion !=4) {
						throw new Exception ("Pack index file version ("+ packindexFileVersion + ") is only compatible with pack file version 4. Pack file version (" + packFileVersion + ") was found");
					}
	
					int packEntrySizeArray [] = new int [256];
					for (int i=0; i< 256; i++) {
						packEntrySizeArray[i] = packindexfiledataBuffer.getInt();
					}
					//get the total number of entries, as being the number of entries from the final fanout table entry.
					indexEntryCount = packEntrySizeArray[255];
					//validate that this matches the number of entries in the pack file, according to its header.
					if ( indexEntryCount != packEntryCount ) {
						throw new Exception ("The entry count ("+ indexEntryCount + ") from the pack index does not match the entry count (" + packEntryCount + ") from the pack file");
					}
					
					//in version 3 of the pack index file, the SHA1 table moves from the pack index file to the pack file (necessitating a version 4 pack file, as noted earlier)
					//in versions < 3 of the index file, the SHA1 data lives in the index file in some manner (differs between version 1, and versions 2,3).
					if (packindexFileVersion < 3) {
						sha1Index = Integer.MAX_VALUE;
	    				//read the series of 20 byte sha1 entries.
	    				//ours *should* be in here somewhere.. find it
	    				//make sure to read *all* of the entries from the file (or else seek to the end of the data), so the parsing logic is not broken.
	    				//TODO: use a binary search to find this in a more efficient manner
	    				
	    				for (int i=0; i< indexEntryCount; i++) {
	    					byte [] indexEntryIdBuffer = new byte [20];
	    					packindexfiledataBuffer.get(indexEntryIdBuffer);
	    					String indexEntrySha1 = Hex.encodeHexString( indexEntryIdBuffer );
	    					if ( indexEntrySha1.equals(filesha1) ) {
	    						if (log.isDebugEnabled()) log.debug("FOUND our SHA1 "+ indexEntrySha1+ " at entry " + i + " in the SHA11 table");
	    						sha1Index=i;
	    					}
	    				}
					}
					//read the CRCs for the various entries (and throw them away, for now)
					byte [] crcs = new byte [indexEntryCount * 4];
					packindexfiledataBuffer.get(crcs);
					
					//read the offsets for the various entries. We need to know the offset into the pack file of the SHA11 entry we are looking at
					//NB: the various tables in the "pack index" file are sorted by the corresponding SHA1.
					//2 adjacent entries in the offset table (for consequtive SHA11 entries) could have wildly different offsets into the "pack" file
					//and the offsets in the table are therefore not sorted by offset.
					//In order to calculate the deflated length of an entry in the pack file (which is not stored anywhere), 
					//we need to generate an extra offset table, ordered by the offset. We will then look for the next ordered offset, and store it alongside
					//the offset of the SHA1 we're interested in.
					packEntryOffsetArray = new int [indexEntryCount];
					packEntryOffsetArrayOrdered = new int [indexEntryCount];
					for (int i=0; i< indexEntryCount; i++) {
						packEntryOffsetArray[i]=packindexfiledataBuffer.getInt();
						packEntryOffsetArrayOrdered[i]=packEntryOffsetArray[i];
					}								
    			}
    			//now we're out of the pack index file version 1 or 2/3 specific stuff.. the rest of the logic is fairly common (execept for the "pack" file version 4 stuff, of course! :)    			
				Arrays.sort (packEntryOffsetArrayOrdered);

				//take account of the 20 byte sha1 checksum after all the individual entries
				int nextOffset = packfiledata.length -20;	
				//get the first offset greater than the offset of our sha1. since the table is ordered by offset, these 2 offsets gives us the deflated length of the entry
				for (int i = 0; i < indexEntryCount; i++) { 
					if ( packEntryOffsetArrayOrdered[i] > packEntryOffsetArray[sha1Index]) {
						nextOffset=packEntryOffsetArrayOrdered[i];
						if (log.isDebugEnabled()) log.debug("Found the entry with the next offset: "+ nextOffset);
						if ( nextOffset >  ( packfiledata.length - 1)) 
							throw new Exception ("A 'next' offset of "+ nextOffset+ " is not feasible for a pack file with length "+ packfiledata.length);
						break;
					}
				}
				//given the "pack" file offsets, we know the deflated length of the entry in there.
				int entryLength = (nextOffset - packEntryOffsetArray[sha1Index] ) ;
				if (log.isDebugEnabled()) { 
						log.debug("Our offset into the pack file is " + packEntryOffsetArray[sha1Index]);
						log.debug("The offset of the next entry into the pack file is " + nextOffset);
						log.debug("The deflated entry length, based on offset differences, is " + entryLength);
				}

				//No need to read the remainder of the "pack index" file at this point.. (for either version 1, or versions 2/3)
				//so start reading the pack file again.
				//wrap the entry we are interested in in a ByteBuffer (using the offsets to calculate the length)
				//Note: the offset is from the start of the "pack" file, not from after the header.
				ByteBuffer entryBuffer = ByteBuffer.wrap(packfiledata, packEntryOffsetArray[sha1Index], entryLength);
				byte typeandsize = entryBuffer.get(); //size byte #1: 4 bits of size data available
				//get bits 6,5,4 into a byte, as the least significant bits. So if  typeandsize = bXYZbbbbb, then entryType = 00000XYZ
				//TODO: there may be a change required here for version 4 "pack" files, which use a 4 bit type, rather than a 3 bit type in earlier versions.
				//but maybe not, because we only handle one type (for blocbs), which probably does not set the highest bit in the "type" nibble.
				byte entryType = (byte)((typeandsize & (byte)0x70) >> 4); 
				if ( entryType != 0x3 ) { 
					//there are various entry types, but the only one we will attempt to handle (because its the only one we should get) is the Git OBJ_BLOB
					//entry type, which means that the SHA11 relates to a Git blob.
					throw new Exception ("This logic only handles SHA1 values which correspond to Git BLOBs, if the object is packed.");
				}

				//Note that 0x7F is 0111 1111 in binary. Useful to mask off all but the top bit of a byte
				// and that 0x80 is 1000 0000 in binary. Useful to mask off the lower bits of a byte
				// and that 0x70 is 0111 0000 in binary. Used above to mask off 3 bits of a byte
				// and that  0xF is 0000 1111 in binary.
				
				//get bits 2,1,0 into a byte, as the least significant bits. So if  typeandsize = bbbbbbXYZ, then entrySizeNibble = 00000XYZ
				//get the lower 4 bits of the byte as the first size byte				  
				byte entrySizeNibble = (byte)((typeandsize & (byte)0xF) ); 
				int entrySizeWhenInflated = (int)entrySizeNibble;

				//set up to check if the "more" flag is set on the entry+size byte, then look at the next byte for size..
				byte nextsizebyte =  (byte) (typeandsize & (byte)0x80);

				//the next piece of logic decodes the variable length "size" information, which comes in an initial 4 bit, followed by potentially multiple additional 7 bit chunks.
				//(3 bits type for versions < 4, or 4 bits for version 4 "pack" files)
				int sizebytescounted = 1; 
				if ( (nextsizebyte & 0x80) > 0 ) {
					//top bit is set on nextsizebyte, so we need to get the next byte as well
					if ( sizebytescounted > 4 ) {
						//this should not happen. the size shoud be determined by a max of 4 bytes.
						throw new Exception ("The number of entry size bytes read exceeds 4. Either data corruption, or a parsing error has occurred");
					}
					nextsizebyte = entryBuffer.get();
					entrySizeWhenInflated = ( (((int)(nextsizebyte & 0x7F))<<(4+(7*(sizebytescounted-1)))) | entrySizeWhenInflated);
					sizebytescounted++;
				}

				if (log.isDebugEnabled()) log.debug("The size of the inflated entry should be " + entrySizeWhenInflated + ", binary: " + Integer.toBinaryString(entrySizeWhenInflated) );

				//extract the data from the "pack" file, taking into account its total size, based on the offsets, and the number of type and size bytes already read.
				int entryDataBytesToRead = entryLength - sizebytescounted;
				if (log.isDebugEnabled()) log.debug("Read " + sizebytescounted + " size bytes, so will read " + entryDataBytesToRead + " bytes of entry data from the 'pack' file");

				byte deflatedSource [] = new byte [entryDataBytesToRead];
				entryBuffer.get(deflatedSource);
				byte []  inflatedData = inflate (deflatedSource, 1024);
				
				//validate that entrySizeWhenInflated == the actual size of the inflated data (probably not an issue, because the inflate would very likely fail if the data or length were wrong)
				if ( entrySizeWhenInflated != inflatedData.length )
					throw new Exception ("The predicted inflated length of the entry was "+ entrySizeWhenInflated + ", when we inflated the entry, we got data of length " + inflatedData.length);

				//finally..
				return inflatedData;
    		}
    	}
    	
    	/**
    	 * gets a Map of relative file paths to SHA1s using raw Git index file data
    	 * @param data the raw binary data from a valid Git index file (Versions 2,3,4 are supported)
    	 * @return a Map of relative file paths to SHA1s using raw Git index file data
    	 * @todo consider sharing this method between the Git Spider, and the SourceCodeDisclosure scanner. 
    	 */
    	@SuppressWarnings("unused")
		public Map <String, String> getIndexSha1s (byte [] data) throws Exception {
    		Map <String, String> map = new TreeMap <String, String> (); 
    		
    		//wrap up the data, so we can read it..
			ByteBuffer dataBuffer = ByteBuffer.wrap(data);
			
			byte [] dircArray = new byte [4];
			dataBuffer.get(dircArray);
			
			int indexFileVersion = dataBuffer.getInt();
			if ( log.isDebugEnabled() ) log.debug("The Git index file version is "+ indexFileVersion);
			
			int indexEntryCount = dataBuffer.getInt();
			if ( log.isDebugEnabled() ) log.debug(indexEntryCount + " entries were found in the Git index file ");

			if ( indexFileVersion != 2 && indexFileVersion != 3 && indexFileVersion != 4) {
				throw new Exception ("Only Git Index File versions 2, 3, and 4 are currently supported. Git Index File Version "+ indexFileVersion + " was found.");
			}
			
			//for version 4 (and upwards?), we need to know the previous entry name, so store it
			String previousIndexEntryName = "";
			for (int entryIndex = 0; entryIndex < indexEntryCount; entryIndex ++) {
				int entryBytesRead = 0;
				int indexEntryCtime1 = dataBuffer.getInt(); entryBytesRead+=4;
				if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has indexEntryCtime1 "+ indexEntryCtime1);							
				int indexEntryCtime2 = dataBuffer.getInt();	entryBytesRead+=4;
				int indexEntryMtime1 = dataBuffer.getInt(); entryBytesRead+=4;
				int indexEntryMtime2 = dataBuffer.getInt(); entryBytesRead+=4;
				int indexEntryDev = dataBuffer.getInt(); entryBytesRead+=4;
				int indexEntryInode = dataBuffer.getInt(); entryBytesRead+=4;
				int indexEntryMode = dataBuffer.getInt(); entryBytesRead+=4;
				int indexEntryUid = dataBuffer.getInt(); entryBytesRead+=4;
				int indexEntryGid = dataBuffer.getInt(); entryBytesRead+=4;
				int indexEntrySize = dataBuffer.getInt(); entryBytesRead+=4;	
				if ( log.isDebugEnabled() ) log.debug("Entry "+ entryIndex + " has size "+ indexEntrySize);
				
				//size is unspecified for the entry id, but it seems to be 40 bytes SHA-1 string
				//stored as 20 bytes, network order
				byte [] indexEntryIdBuffer = new byte [20];
				dataBuffer.get(indexEntryIdBuffer);	entryBytesRead+=20;
				String indexEntrySha1 = Hex.encodeHexString( indexEntryIdBuffer );						
				
				short indexEntryFlags = dataBuffer.getShort(); entryBytesRead+=2;						
				if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has flags " + indexEntryFlags);

				//mask off all but the least significant 12 bits of the index entry flags to get the length of the name in bytes 
				int indexEntryNameByteLength = indexEntryFlags & (int)4095;						
				if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has a name of length " + indexEntryNameByteLength);

				//mask off all but the second most significant 12 bit of the index entry flags to get the extended flag for the entry 
				//int indexEntryExtendedFlag = indexEntryFlags & (int)16384;
				int indexEntryExtendedFlag = ((indexEntryFlags & (int)(1<<14) )>>14);
				if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has an extended flag of " + indexEntryExtendedFlag);

				//check that we parsed out the index entry extended flag correctly.
				//this is more of an assertion than anything. It's already saved my bacon once.
				if (indexEntryExtendedFlag != 0 && indexEntryExtendedFlag != 1 ) {
					throw new Exception ("Error parsing out the extended flag for index entry "+ entryIndex + ". We got "+ indexEntryExtendedFlag);
				}
				if ( indexFileVersion == 2 && indexEntryExtendedFlag != 0) {
					throw new Exception ("Index File Version 2 is supposed to have the extended flag set to 0. For index entry "+ entryIndex + ", it is set to "+ indexEntryExtendedFlag);
				}
				
				//specific to version 3 and above, if the extended flag is set for the entry.
				if (indexFileVersion > 2 && indexEntryExtendedFlag == 1) {
					if ( log.isDebugEnabled() ) log.debug ("For Index file version "+ indexFileVersion +", reading an extra 16 bits for Entry "+ entryIndex );
					short indexEntryExtendedFlags = dataBuffer.getShort(); entryBytesRead+=2;						
					if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has (optional) extended flags " + indexEntryExtendedFlags);
					}
				
				String indexEntryName = null;
				if ( indexFileVersion > 3 ) {
					if ( log.isDebugEnabled() ) log.debug("Inflating the (deflated) entry name for index entry "+ entryIndex + " based on the previous entry name, since Index file version "+ indexFileVersion + " requires this");
												
					//get bytes until we find one with the msb NOT set. count the bytes.
					int n = 0, removeNfromPreviousName = 0;
					byte msbsetmask = (byte)(1<<7); 						// 1000 0000
					byte msbunsetmask = (byte) ((~ msbsetmask) & 0xFF );  	// 0111 1111
					while (++n > 0) {
						byte byteRead = dataBuffer.get(); entryBytesRead++;
						if (n==1)	//zero the msb of the first byte read
							removeNfromPreviousName = (removeNfromPreviousName << 8 ) | (0xFF & ( byteRead & msbunsetmask));
						else 		//set the msb of subsequent bytes read
							removeNfromPreviousName = (removeNfromPreviousName << 8 ) | (0xFF & ( byteRead | msbsetmask));
						if ( ( byteRead & msbsetmask) == 0 ) break;  //break if msb is NOT set in the byte
					}

					if (log.isDebugEnabled()) log.debug("We read "+ n + " bytes of variable length data from before the start of the entry name");
					if ( n > 4 ) 
						throw new Exception ("An entry name is never expected to be > 2^^32 bytes long. Some file corruption may have occurred, or a parsing error has occurred");
													
					//now read the (partial) name for the current entry
					int bytesToReadCurrentNameEntry = indexEntryNameByteLength- (previousIndexEntryName.length() - removeNfromPreviousName);
					byte [] indexEntryNameBuffer = new byte [bytesToReadCurrentNameEntry];
					dataBuffer.get(indexEntryNameBuffer); entryBytesRead+=bytesToReadCurrentNameEntry;

					//build it up
					indexEntryName = previousIndexEntryName.substring(0, previousIndexEntryName.length() - removeNfromPreviousName) + new String (indexEntryNameBuffer);
				} else {
					//indexFileVersion <= 3 (waaaaay simpler logic, but the index file is larger in this version than for v4+)
					byte [] indexEntryNameBuffer = new byte [indexEntryNameByteLength];
					dataBuffer.get(indexEntryNameBuffer); entryBytesRead+=indexEntryNameByteLength;
					indexEntryName = new String (indexEntryNameBuffer);
				}
				
				if ( log.isDebugEnabled() ) log.debug("Entry "+ entryIndex + " has name "+ indexEntryName);
				
				//and store off the index entry name, for the next iteration
				previousIndexEntryName=indexEntryName;
				//skip past the zero byte terminating the string (whose purpose seems completely pointless to me, but hey)
				byte indexEntryNul = dataBuffer.get(); entryBytesRead++;
				
				//the padding after the pathname does not exist for versions 4 or later. 
				if ( indexFileVersion < 4 ) {
					if ( log.isDebugEnabled() ) log.debug("Aligning to an 8 byte boundary after Entry "+ entryIndex + ", since Index file version "+ indexFileVersion + " mandates 64 bit alignment for index entries");
				
					int entryBytesToRead=((8-(entryBytesRead%8))%8); 
					if ( log.isDebugEnabled() ) {
						log.debug ("The number of bytes read for index entry "+ entryIndex + " thus far is: "+ entryBytesRead);
						log.debug ("So we must read "+ entryBytesToRead + " bytes to stay on a 64 bit boundary");
						}
					//read the 0-7 (NUL) bytes to keep reading index entries on an 8 byte boundary
					byte [] indexEntryPadBuffer = new byte [entryBytesToRead];
					dataBuffer.get(indexEntryPadBuffer); entryBytesRead+=entryBytesToRead;
					} 
				else {
					if ( log.isDebugEnabled() ) log.debug("Not aligning to an 8 byte boundary after Entry "+ entryIndex + ", since Index file version "+ indexFileVersion + " does not mandate 64 bit alignment for index entries");
					}
											
				//Git does not store entries for directories, but just files/symlinks/Git links, so no need to handle directories here, unlike with SVN, for instance.
				if ( indexEntryName != null && indexEntryName.length() > 0 ) {
					log.info("Found file/symbolic link/gitlink "+ indexEntryName + " in the Git entries file");
					map.put("../" + indexEntryName, indexEntrySha1);
				}
			}
			return map;
    	}

    	/**
    	 * gets the base folder (ie, the ".git" folder), for the specified Git file
    	 * @param gitFile a valid Git repository file, such as "/XYZ/.git/index" 
    	 * @return the base folder (ie, the ".git" folder), for the specified Git file
    	 */
    	public String getBaseFolder (String gitFile) {
    		Matcher matcher= basefolderpattern.matcher(gitFile);
    		if (matcher.matches()) return matcher.group (1);	
    		return null;
    	}

    	/**
    	 * validate a SHA1 for at least superficially valid from the point of view of Git
    	 * @param sha1 the SHA1 value to validate
    	 * @return true if the SHA1 is at least superficially valid. 
    	 */
    	public boolean validateSHA1 (String sha1) {
    		if ( sha1.length()!= 40) return false;		//40 characters long		
    		if (! sha1pattern.matcher(sha1).find()) return false;  //where each character must be 0-9, or a-f.
    		return true;
    	}

    }
    
    /**
     * thrown if an index file is not a valid V1 "pack index" file.
     * @author 70pointer@gmail.com
     *
     */
    public class NotV1PackIndexFileException extends Exception {

		/**
		 * 
		 */
		private static final long serialVersionUID = 664525398598253409L;    	
    	
    }
}
