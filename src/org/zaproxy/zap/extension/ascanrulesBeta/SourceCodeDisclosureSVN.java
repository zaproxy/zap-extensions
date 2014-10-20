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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.util.Arrays;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * a scanner that looks for application source code disclosure using SVN metadata/file disclosure
 * 
 * @author 70pointer
 *
 */
public class SourceCodeDisclosureSVN extends AbstractAppPlugin {

	/**
	 * details of the vulnerability which we are attempting to find 
	 * 34 = "Predictable Resource Location"
	 */
	private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_34");

	/**
	 * the logger object
	 */
	private static Logger log = Logger.getLogger(SourceCodeDisclosureSVN.class);

	/**
	 * patterns expected in the output for common server side file extensions
	 * TODO: add support for verification of other file types, once I get some real world test cases.
	 */
	private static final Pattern PATTERN_JSP = Pattern.compile("<%.*%>");
	private static final Pattern PATTERN_PHP = Pattern.compile("<?php");
	private static final Pattern PATTERN_JAVA = Pattern.compile("class");  //Java is compiled, not interpreted, but this helps with my test cases.
	private static final Pattern PATTERN_HTML = Pattern.compile("<html");  //helps eliminate some common false positives in the case of 403s, 302s, etc

	/**
	 * returns the plugin id
	 */
	@Override
	public int getId() {
		return 42;
	}

	/**
	 * returns the name of the plugin
	 */
	@Override
	public String getName() {
		return Constant.messages.getString("ascanbeta.sourcecodedisclosure.svnbased.name");
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
	}

	@Override
	public void scan() {
		//at Low or Medium strength, do not attack URLs which returned "Not Found"
		AttackStrength attackStrength = getAttackStrength();
		if ( (attackStrength==AttackStrength.LOW||attackStrength==AttackStrength.MEDIUM) 
				&& (getBaseMsg().getResponseHeader().getStatusCode() == HttpStatus.SC_NOT_FOUND))
			return;
		
		// scan the node itself (ie, at URL level, rather than at parameter level)
		if (log.isDebugEnabled()) {
			log.debug("Attacking at Attack Strength: " + this.getAttackStrength());
			log.debug("Checking [" + getBaseMsg().getRequestHeader().getMethod() + "] ["
					+ getBaseMsg().getRequestHeader().getURI() + "], for Source Code Disclosure using SVN meta-data");
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
			} else {
				if (log.isDebugEnabled()) {
					log.debug ("The URI has no filename component, so there is not much point in looking for corresponding source code!");
				}
			}
		} catch (Exception e) {
			log.error("Error scanning a request for SVN based Source Code Disclosure: " + e.getMessage(), e);
		}
	}


	/**
	 * returns whether the message response content matches the specified extension
	 * @param data
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
			} else if (fileExtension.equals ("HTML")) {
				if ( PATTERN_HTML.matcher(new String(data)).find() ) return true; 
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
		return 34;  //Predictable Resource Location
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
							Constant.messages.getString("ascanbeta.sourcecodedisclosure.svnbased.name"),
							Constant.messages.getString("ascanbeta.sourcecodedisclosure.desc"), 
							getBaseMsg().getRequestHeader().getURI().getURI(),
							null, 
							attackFilename,
							Constant.messages.getString("ascanbeta.sourcecodedisclosure.svnbased.extrainfo", filename, attackFilename),
							Constant.messages.getString("ascanbeta.sourcecodedisclosure.svnbased.soln"),
							null,
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
}
