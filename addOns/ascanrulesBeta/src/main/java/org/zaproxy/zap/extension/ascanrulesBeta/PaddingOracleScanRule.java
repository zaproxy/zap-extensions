/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.regex.Pattern;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

/** @author yhawke (2014) */
public class PaddingOracleScanRule extends AbstractAppParamPlugin {

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
    private static final Logger log = Logger.getLogger(PaddingOracleScanRule.class);

    @Override
    public int getId() {
        return 90024;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.paddingoracle.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.paddingoracle.desc");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.paddingoracle.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.paddingoracle.refs");
    }

    @Override
    public int getCweId() {
        return 209;
    }

    @Override
    public int getWascId() {
        // There's not a real classification for this
        // so we consider the general "Improper Input Handling" class
        // http://projects.webappsec.org/w/page/13246933/Improper%20Input%20Handling
        return 20;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

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

                // If the control test returned an error, then keep going
                if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {

                    // Response without any modification
                    String controlResponse = msg.getResponseBody().toString();

                    // The first test is going to change the last bit
                    oracle[oracle.length - 1] ^= 0x1;
                    encodedValue = encoder.encode(oracle);
                    setParameter(msg, paramName, encodedValue);
                    sendAndReceive(msg);

                    // First check if an Internal Server Error ws launched
                    // in this case we found (very) likely Padding Oracle vulnerability
                    if (msg.getResponseHeader().getStatusCode()
                            == HttpStatusCode.INTERNAL_SERVER_ERROR) {
                        // We Found IT!
                        // First do logging
                        if (log.isDebugEnabled()) {
                            log.debug(
                                    "[Padding Oracle Found] on parameter ["
                                            + paramName
                                            + "] with payload ["
                                            + encodedValue
                                            + "]");
                        }

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(paramName)
                                .setAttack(msg.getRequestHeader().getURI().toString())
                                .setEvidence(msg.getResponseHeader().getReasonPhrase())
                                .setMessage(msg)
                                .raise();
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
                            if (log.isDebugEnabled()) {
                                log.debug(
                                        "[Padding Oracle Found] on parameter ["
                                                + paramName
                                                + "] with payload ["
                                                + encodedValue
                                                + "]");
                            }

                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setParam(paramName)
                                    .setAttack(msg.getRequestHeader().getURI().toString())
                                    .setEvidence(pattern)
                                    .setMessage(msg)
                                    .raise();

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
                // Do not try to internationalise this.. we need an error message in any event..
                // if it's in English, it's still better than not having it at all.
                log.warn(
                        "Padding Oracle vulnerability check failed for parameter ["
                                + paramName
                                + "] and payload ["
                                + encoder.encode(oracle)
                                + "] due to an I/O error",
                        ex);
            }
        }

        return false;
    }

    /**
     * Decide if the data given in 'data' is encrypted It turns out that this is difficult to do on
     * short strings, so we are going to solve this by cheating. Basically, check if the string
     * contains any non-ascii characters (&lt;0x20 or &gt;0x7F). The odds of a 4-character encrypted
     * string having at least one character that falls outside of ASCII is almost 100%. We also
     * ignore any string longer than 16 bytes, since those are generally too short to be encrypted.
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
     * Enumeration Utility which is able to manage all specifi encoding/decoding tasks that could be
     * met during rule's testing
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

                    } catch (DecoderException ex) {
                    }
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
                    if (((last + (int) value.charAt(last)) % 4) == 0) {
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
