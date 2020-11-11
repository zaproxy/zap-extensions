/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.saml;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;

/** Contains some frequent methods related to decoding and encoding SAML messages */
public class SAMLUtils {
    private static final int MAX_INFLATED_SIZE = 100000;

    protected static final Logger log = Logger.getLogger(SAMLUtils.class);

    /** Private constructor, because this class is and Util class and the methods are static */
    private SAMLUtils() {}

    /**
     * Base 64 decode a given string and gives the decoded data as a byte array
     *
     * @param message The String to base 64 decode
     * @return Byte array of the decoded string
     * @throws SAMLException
     */
    public static byte[] b64Decode(String message) throws SAMLException {
        try {
            return Base64.getDecoder().decode(message);
        } catch (IllegalArgumentException e) {
            throw new SAMLException("Base 64 Decode of failed for message: \n" + message, e);
        }
    }

    /**
     * Base 64 encode the given byte array and gives the encoded string
     *
     * @param data The data to encode
     * @return Encoded string
     */
    public static String b64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Inflate a message (that had been deflated) and gets the original message
     *
     * @param data Byte array of deflated data that need to be inflated
     * @return Original message after inflation
     * @throws SAMLException
     */
    public static String inflateMessage(byte[] data) throws SAMLException {
        try {
            byte[] out = data;
            int length = data.length;
            try {
                Inflater inflater = new Inflater(true);
                inflater.setInput(data);
                byte[] xmlMessageBytes = new byte[MAX_INFLATED_SIZE];
                int inflatedLength = inflater.inflate(xmlMessageBytes);
                if (!inflater.finished()) {
                    throw new SAMLException(
                            "Out of space allocated for inflated data ("
                                    + (MAX_INFLATED_SIZE / 1000)
                                    + "kb)");
                }
                inflater.end();
                out = xmlMessageBytes;
                length = inflatedLength;
            } catch (DataFormatException e) {
                log.debug("Inflate SAML message failed - Invalid data format", e);
            }
            return new String(out, 0, length, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException("Data is not in valid encoding format", e);
        }
    }

    /**
     * Deflate a message to be send over a preferred binding
     *
     * @param message Message to be deflated
     * @return The deflated message as a byte array
     */
    public static byte[] deflateMessage(String message) throws SAMLException {
        try {
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    DeflaterOutputStream deflaterOutputStream =
                            new DeflaterOutputStream(byteArrayOutputStream, deflater)) {
                deflaterOutputStream.write(message.getBytes("UTF-8"));
                deflaterOutputStream.finish();
                return byteArrayOutputStream.toByteArray();
            }
        } catch (Exception e) {
            throw new SAMLException("Message Deflation failed", e);
        }
    }

    /**
     * Check whether the httpMessage has a saml message in its parameters
     *
     * @param message The HttpMessage to be checked for
     * @return whether the message has got a saml message within it
     */
    public static boolean hasSAMLMessage(HttpMessage message) {
        return inspectMessage(message).hasSAMLMessage();
    }

    /**
     * Check whether the httpMessage has a saml message in its parameters
     *
     * @param message The HttpMessage to be checked for
     * @return the inspection result of the message
     */
    public static SAMLInspectionResult inspectMessage(HttpMessage message) {
        for (HtmlParameter parameter : message.getUrlParams()) {
            if (isSAMLParameter(parameter)) {
                return new SAMLInspectionResult(parameter);
            }
        }
        for (HtmlParameter parameter : message.getFormParams()) {
            if (isSAMLParameter(parameter)) {
                return new SAMLInspectionResult(parameter);
            }
        }
        return SAMLInspectionResult.NOT_SAML;
    }

    private static boolean isSAMLParameter(HtmlParameter parameter) {
        return (parameter.getName().equals("SAMLRequest")
                        || parameter.getName().equals("SAMLResponse"))
                && isNonEmptyValue(parameter.getValue());
    }

    private static boolean isNonEmptyValue(String param) {
        return param != null && !"".equals(param);
    }

    /**
     * Decode the SAML messages based on the binding used
     *
     * @param val the SAML message to decode
     * @param binding The binding used
     * @return The decoded SAML message if success, or the original string if failed
     */
    public static String extractSAMLMessage(String val, Binding binding) {
        try {
            switch (binding) {
                case HTTPPost:
                    val = URLDecoder.decode(val, "UTF-8");
                    byte[] b64decoded = b64Decode(val);
                    return inflateMessage(b64decoded);
                case HTTPRedirect:
                    b64decoded = b64Decode(val);
                    return inflateMessage(b64decoded);
                default:
                    break;
            }
        } catch (UnsupportedEncodingException | SAMLException e) {
            log.error(e);
        }
        return "";
    }
}
