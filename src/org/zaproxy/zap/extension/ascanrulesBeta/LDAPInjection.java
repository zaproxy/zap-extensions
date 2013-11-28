/**
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * The LDAPInjection plugin identifies LDAP injection vulnerabilities with GET,
 * POST, and cookie parameters, as well as Headers.
 *
 * @author Colm O'Flaherty, Encription Ireland Ltd
 */
public class LDAPInjection extends AbstractAppParamPlugin {

    /**
     * plugin dependencies
     */
    private static final String[] dependency = {};
    /**
     * for logging.
     */
    private static Logger log = Logger.getLogger(LDAPInjection.class);
    /**
     * determines if we should output Debug level logging
     */
    private boolean debugEnabled = log.isDebugEnabled();
    private static final String errorAttack = "|!<>=~=>=<=*(),+-\"'\\/&;";
    //Note the ampersand at the end.. causes problems if earlier in the string..
    //and the semicolon after that..
    // ZAP: Added a static error bundle to speed up the implementation
    // LDAP errors for Injection testing
    // Use an inverse map to avoid multimap use
    // ----------------------------------------
    private static final Map<Pattern, String> LDAP_ERRORS = new HashMap<Pattern, String>();
    static {
        String ldapImplementationsFlat = Constant.messages.getString("ascanbeta.ldapinjection.knownimplementations");
        String[] ldapImplementations = ldapImplementationsFlat.split(":");
        String errorMessageFlat;
        String[] errorMessages;
        Pattern errorPattern;

        for (String ldapImplementation : ldapImplementations) {  //for each LDAP implementation
            //for each known LDAP implementation
            errorMessageFlat = Constant.messages.getString("ascanbeta.ldapinjection." + ldapImplementation + ".errormessages");
            errorMessages = errorMessageFlat.split(":");

            for (String errorMessage : errorMessages) {  //for each error message for the given LDAP implemention
                //compile it into a pattern
                errorPattern = Pattern.compile(errorMessage);

                //add it to the errors list together with the ldap implementation
                LDAP_ERRORS.put(errorPattern, ldapImplementation);
            }
        }
    }

    @Override
    public int getId() {
        return 40015;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.ldapinjection.name");
    }

    @Override
    public String[] getDependency() {
        return dependency;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.ldapinjection.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.ldapinjection.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.ldapinjection.refs");
    }

    @Override
    public void init() {
        //DEBUG: turn on for debugging
        //log.setLevel(org.apache.log4j.Level.DEBUG);
        //this.debugEnabled = true;

        if (this.debugEnabled) {
            log.debug("Initialising");
        }
    }

    /**
     * scans the user specified parameter for LDAP injection
     * vulnerabilities. Requires one extra request for each parameter checked
     */
	public void scan(HttpMessage msg, String paramname, String paramvalue) {
		
        try {
                HttpMessage attackMsg = getNewMsg();
                
                if (this.debugEnabled) {
                    log.debug("Scanning URL [" + attackMsg.getRequestHeader().getMethod() + "] [" + attackMsg.getRequestHeader().getURI() + "],  [" + paramname + "] with value [" + paramvalue + "] for LDAP Injection");
                }
                
                //set a new parameter.. with a value designed to cause an LDAP error to occur
                this.setParameter(attackMsg, paramname, errorAttack);
                
                //send it, and see what happens :)
                sendAndReceive(attackMsg);
                checkResultsForAlert(attackMsg, /*currentHtmlParameter.getType().toString(), */ paramname);

        } catch (Exception e) {
            //Do not try to internationalise this.. we need an error message in any event.. 
            //if it's in English, it's still better than not having it at all. 
            log.error("An error occurred checking a url for LDAP Injection issues", e);
        }
    }

    /**
     * returns does the Message Response match the pattern provided?
     *
     * @param msg the Message whose response we will examine
     * @param pattern the pattern which we will look for in the Message Body
     * @return true/false. D'uh! (It being a boolean, and all that)
     */
    protected boolean responseMatches(HttpMessage msg, Pattern pattern) {
        Matcher matcher = pattern.matcher(msg.getResponseBody().toString());
        return matcher.find();
    }

    /**
     *
     * @param message
     * @param parameterType
     * @param parameterName
     * @return
     * @throws Exception
     */
    private boolean checkResultsForAlert(HttpMessage message, /*String parameterType, */ String parameterName) throws Exception {
        //compare the request response with each of the known error messages, 
        //for each of the known LDAP implementations.
        //in order to minimise false positives, only consider a match 
        //for the error message in the response if the string also 
        //did NOT occur in the original (unmodified) response
        for (Pattern errorPattern : LDAP_ERRORS.keySet()) {

            //if the pattern was found in the new response, 
            //but not in the original response (for the unmodified request)
            //and the new response was OK (200), then we have a match.. LDAP injection!
            if (message.getResponseHeader().getStatusCode() == HttpStatusCode.OK
                    && responseMatches(message, errorPattern)
                    && !responseMatches(getBaseMsg(), errorPattern)) {

                //response code is ok, and the HTML matches one of the known LDAP errors.
                //so raise the error, and move on to the next parameter
                String extraInfo = Constant.messages.getString("ascanbeta.ldapinjection.alert.extrainfo",
                        /*parameterType,*/
                        parameterName,
                        getBaseMsg().getRequestHeader().getMethod(),
                        getBaseMsg().getRequestHeader().getURI().getURI(),
                        errorAttack, 
                        LDAP_ERRORS.get(errorPattern), 
                        errorPattern);

                String attack = Constant.messages.getString("ascanbeta.ldapinjection.alert.attack", /*parameterType, */ parameterName, errorAttack);
                String vulnname = Constant.messages.getString("ascanbeta.ldapinjection.name");
                String vulndesc = Constant.messages.getString("ascanbeta.ldapinjection.desc");
                String vulnsoln = Constant.messages.getString("ascanbeta.ldapinjection.soln");

                bingo(Alert.RISK_HIGH, Alert.WARNING, vulnname, vulndesc,
                        getBaseMsg().getRequestHeader().getURI().getURI(),
                        parameterName, 
                        attack,
                        extraInfo, 
                        vulnsoln, 
                        getBaseMsg());

                //and log it
                String logMessage = Constant.messages.getString("ascanbeta.ldapinjection.alert.logmessage",
                        getBaseMsg().getRequestHeader().getMethod(),
                        getBaseMsg().getRequestHeader().getURI().getURI(),
                        /* parameterType, */
                        parameterName,
                        errorAttack, 
                        LDAP_ERRORS.get(errorPattern), 
                        errorPattern);

                log.info(logMessage);

                return true;  //threw an alert
            }

        } //for each error message for the given LDAP implemention

        return false;  //did not throw an alert
    }

    /**
     *
     * @return
     */
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    /**
     *
     * @return
     */
    @Override
    public int getCweId() {
        return 90;
    }

    /**
     *
     * @return
     */
    @Override
    public int getWascId() {
        return 29;
    }

}
