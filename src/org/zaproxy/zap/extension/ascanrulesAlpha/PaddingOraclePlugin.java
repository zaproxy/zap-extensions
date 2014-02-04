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

import java.io.IOException;
import java.util.regex.Pattern;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

/**
 *
 * @author yhawke (2014)
 */
public class PaddingOraclePlugin extends AbstractAppParamPlugin {

    // List of all possible errors
    private static final String[] ERROR_PATTERNS = {
        "BadPaddingException", 
        "padding", 
        "runtime", 
        "runtime error", 
        "server error", 
        "cryptographicexception", 
        "crypto"
    };

    // Logger object
    private static Logger log = Logger.getLogger(PaddingOraclePlugin.class);    
    
    /**
     * Get the unique identifier of this plugin
     * @return this plugin identifier
     */
    @Override
    public int getId() {
        return 90024;
    }

    /**
     * Get the name of this plugin
     * @return the plugin name
     */
    @Override
    public String getName() {
        return "Generic Padding Oracle";
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
        return "By manipulating the padding on an encrypted string, an attacker is able"
                + "to generate an error message that indicates a likely 'padding oracle' vulnerability. "
                + "Such a vulnerability can affect any application or framework that uses encryption improperly, "
                + "such as some versions of ASP.net, Java Server Faces, and Mono. "
                + "An attacker may exploit this issue to decrypt data and recover encryption keys, "
                + "potentially viewing and modifying confidential data. "
                + "This plugin should detect the MS10-070 padding oracle vulnerability in ASP.net "
                + "if CustomErrors are enabled for that.";
    }

    /**
     * Give back the categorization of the vulnerability 
     * checked by this plugin (it's an injection category for CODEi)
     * @return a category from the Category enum list 
     */    
    @Override
    public int getCategory() {
        return Category.MISC;
    }

    /**
     * Give back a general solution for the found vulnerability
     * @return the solution that can be put in place
     */
    @Override
    public String getSolution() {        
        return "Update the affected server software, or modify the scripts "
                + "so that they properly validate encrypted data before "
                + "attempting decryption.";    
    }

    /**
     * Reports all links and documentation which refers to this vulnerability
     * @return a string based list of references
     */    
    @Override
    public String getReference() {
        return "http://netifera.com/research/\n"
                + "http://www.microsoft.com/technet/security/bulletin/ms10-070.mspx\n"
                + "http://www.mono-project.com/Vulnerabilities#ASP.NET_Padding_Oracle\n"
                + "https://bugzilla.redhat.com/show_bug.cgi?id=623799";
    }
    
    /**
     * http://cwe.mitre.org/data/definitions/209.html
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        return 209;
    }

    /**
     * @return the official WASC id
     */
    @Override
    public int getWascId() {
        // There's not a real classification for this
        // so we consider the general "Improper Input Handling" class 
        // http://projects.webappsec.org/w/page/13246933/Improper%20Input%20Handling
        return 20;
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
     * Scan for Paddding Oracle Vulnerabilites
     * 
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String paramName, String value) {
        // Get rid of strings that are all numeric 
        // (they probably aren't encoded and they pollute results)
        if (!value.matches("^[0-9]+$")) {
            for (OracleEncoder encoder : OracleEncoder.values()) {
                if (checkPaddingOracle(paramName, value, encoder)) {
                    break;
                }
            }
        }
    }

    /**
     *
     * @param paramName
     * @param value
     * @param encoder
     * @return
     * @throws IOException
     */
    private boolean checkPaddingOracle(String paramName, String value, OracleEncoder encoder) {

        // Get the decoded value
        byte[] oracle = encoder.decode(value);
        if ((oracle != null) && isEncrypted(oracle)) {
            
            try {
                // First test is for double control
                HttpMessage msg = getNewMsg();
                String encodedValue = encoder.encode(oracle);
                setParameter(msg, paramName, encodedValue);
                sendAndReceive(msg);

                // Response without any modification
                String controlResponse = msg.getResponseBody().toString();

                // If the control test returned an error, then keep going
                if (msg.getResponseHeader().getStatusCode() == HttpStatus.SC_OK) {

                    // The first test is going to change the last bit
                    oracle[oracle.length - 1] ^= 0x1;
                    encodedValue = encoder.encode(oracle);
                    setParameter(msg, paramName, encodedValue);
                    sendAndReceive(msg);

                    // First check if an Internal Server Error ws launched
                    // in this case we found (very) likely Padding Oracle vulnerability
                    if (msg.getResponseHeader().getStatusCode() == HttpStatus.SC_INTERNAL_SERVER_ERROR) {
                            // We Found IT!                    
                            // First do logging
                            log.info("[Padding Oracle Found] on parameter [" + paramName + "] with payload [" + encodedValue + "]");

                            // Now create the alert message
                            this.bingo(
                                    Alert.RISK_HIGH,
                                    Alert.WARNING,
                                    null,
                                    paramName,
                                    encodedValue,
                                    null,
                                    HttpStatus.getStatusText(HttpStatus.SC_INTERNAL_SERVER_ERROR),
                                    msg);
                    }

                    // Otherwise check the response with the last bit changed
                    String lastBitResponse = msg.getResponseBody().toString();

                    // Check if changing the last bit produced a result that 
                    // changing the first bit didn't. These results are based
                    // on a list of error strings. 
                    for (String pattern : ERROR_PATTERNS) {
                        
                        if (lastBitResponse.contains(pattern)
                                && !controlResponse.contains(pattern)) {

                            // We Found IT!                    
                            // First do logging
                            log.info("[Padding Oracle Found] on parameter [" + paramName + "] with payload [" + encodedValue + "]");

                            // Now create the alert message
                            this.bingo(
                                    Alert.RISK_HIGH,
                                    Alert.WARNING,
                                    null,
                                    paramName,
                                    encodedValue,
                                    null,
                                    pattern,
                                    msg);

                            // All done. No need to look for vulnerabilities on subsequent 
                            // parameters on the same request (to reduce performance impact)
                            return true;
                        }
                        
                        // Check if the scan has been stopped
                        // if yes dispose resources and exit
                        if (isStop()) {
                            return true;
                        }                        
                    }
                }

            } catch (IOException ex) {
                //Do not try to internationalise this.. we need an error message in any event..
                //if it's in English, it's still better than not having it at all.
                log.error("Padding Oracle vulnerability check failed for parameter ["
                        + paramName + "] and payload [" + encoder.encode(oracle) + "] due to an I/O error", ex);
            }
        }

        return false;
    }

    /**
     * Decide if the data given in 'data' is encrypted
     * It turns out that this is difficult to do on short strings, so we are going to 
     * solve this by cheating. Basically, check if the string contains any non-ascii
     * characters (&lt;0x20 or &gt;0x7F). The odds of a 4-character encrypted string having
     * at least one character that falls outside of ASCII is almost 100%. We also 
     * ignore any string longer than 16 bytes, since those are generally too short
     * to be encrypted. 
     * 
     * @param value the value that need to be checked
     * @return true if it seems to be encrypted
     */
    private boolean isEncrypted(byte[] value) {

        // Make sure we have a reasonable sized string 
        // (encrypted strings tend to be long, and short strings tend to break our numbers)
        if (value.length < 16) {
            return false;
        }

        int notAscii = 0;
        for (int i = 0; i < value.length; i++) {
            if (value[i] < 0x20 || value[i] > 0x7F) {
                notAscii++;
            }
        }

        return (notAscii > (value.length / 4));
    }
    
    
    /**
     * Enumeration Utility which is able to manage all specifi encoding/decoding
     * tasks that could be met during plugin's testing
     */
    public enum OracleEncoder {
        HEX {
            // Hex strings are a-fA-F0-9. Although it's technically possible for a 
            // base64 string to look like this, it's exceptionally unlikely.
            private final Pattern HEX_PATTERN = Pattern.compile("^([a-fA-F0-9]{2})+$");

            @Override
            public String encode(byte[] value) {
                return Hex.encodeHexString(value);
            }

            @Override
            public byte[] decode(String value) {
                if (HEX_PATTERN.matcher(value).matches()) {
                    try {
                        return Hex.decodeHex(value.toCharArray());
                        
                    } catch (DecoderException ex) {}
                }
                
                return null;
            }
        },
        
        BASE64URL {
            // base64url always has an integer 0, 1, or 2 at the end, and contains letters, 
            // numbers, -, and _. The final byte is the number of padding bytes, so the 
            // string length with a number of extra bytes equal to the final digit has to be 
            // a multiple of 4. 
            private final Pattern BASE64URL_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+[012]$");

            @Override
            public String encode(byte[] value) {
                String encoded = Base64.encodeBase64URLSafeString(value);
                int padding = (4 - (encoded.length() % 4)) % 4;
                return encoded + Integer.toString(padding);
            }

            @Override
            public byte[] decode(String value) {
                if (BASE64URL_PATTERN.matcher(value).matches()) {
                    // The last letter represents the length
                    int last = value.length() - 1; 
                    if(((last + (int)value.charAt(last)) % 4) == 0) {
                        Base64 decoder = new Base64(true);
                        return decoder.decode(value.substring(0, last));
                    }
                }
                
                return null;
            }
        },
        
        BASE64 {
            // base64 strings are similar, except they can contain + and /, and end 
            // with 0 - 2 '=' signs. They are also a multiple of 4 bytes. 
            private final Pattern BASE64_PATTERN = Pattern.compile("^[a-zA-Z0-9/+]+={0,2}$");

            @Override
            public String encode(byte[] value) {
                return Base64.encodeBase64String(value);
            }

            @Override
            public byte[] decode(String value) {
                if (BASE64_PATTERN.matcher(value).matches()) {
                    if ((value.length() % 4) == 0) {
                        return Base64.decodeBase64(value);
                    }
                }
                
                return null;
            }
        };
        
        public abstract String encode(byte[] value);
        public abstract byte[] decode(String value);
    }
}
