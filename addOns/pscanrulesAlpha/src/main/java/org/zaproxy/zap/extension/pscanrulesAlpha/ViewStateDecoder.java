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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.apache.commons.codec.binary.Hex;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;

import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.EMPTY_NODE;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.EMPTY_STRING;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.FALSE;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.NULL_TERMINATED_STRING;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.STRING;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.TRUE;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.UNSIGNED_INT;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.ZERO;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.CHARS_TO_ENCODE_IN_XML_PATTERN;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readBytes;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readLittleEndianBase128Number;

/**
 * Decodes a ViewState into an XML based format.
 *
 * @author 70pointer@gmail.com
 */
public class ViewStateDecoder {

    /**
     * Exception class to allow the application to throw custom "Out Of Data" type of exceptions
     *
     * @author root
     */
    private class NoMoreDataException extends Exception {

        /** */
        private static final long serialVersionUID = 428921470671268371L;
    }


    /**
     * decodes a single (ViewState-specific) object from the ByteBuffer.
     *
     * @param bb the ByteBuffer from which to read the next ViewState object
     * @return a StringBuilder containing the human-readable and machine parseable representation
     *     (XML based)
     * @throws NoMoreDataException
     * @throws Exception
     */
    public StringBuilder decodeObjectAsXML(ByteBuffer bb) throws NoMoreDataException, Exception {
        int b = (int) bb.get();
        StringBuilder representation = new StringBuilder();
        Matcher matcher = null;
        boolean malicious = false;
        switch (b) {
            case 0x02:
                return UNSIGNED_INT.decoder.apply(bb).orElseThrow(Exception::new);
            case 0x03:
                // Container of Booleans
                // TODO: test this case.
                int booleancontainersize = readLittleEndianBase128Number(bb);
                representation.append("<booleanarray size=\"" + booleancontainersize + "\">\n");
                for (int i = 0; i < booleancontainersize; i++)
                    representation.append(decodeObjectAsXML(bb));
                representation.append("</booleanarray>\n");
                return representation;
            case 0x05:
            case 0x1E:
                return STRING.decoder.apply(bb).orElseThrow(Exception::new);
            case 0x0B:
                return NULL_TERMINATED_STRING.decoder.apply(bb).orElseThrow(Exception::new);
            case 0x0F:
                // Tuple
                representation.append("<pair>\n");
                representation.append(decodeObjectAsXML(bb));
                representation.append(decodeObjectAsXML(bb));
                representation.append("</pair>\n");
                return representation;
            case 0x10:
                // Triple
                // TODO: test this case.
                representation.append("<triple>\n");
                representation.append(decodeObjectAsXML(bb));
                representation.append(decodeObjectAsXML(bb));
                representation.append(decodeObjectAsXML(bb));
                representation.append("</triple>\n");
                return representation;
            case 0x15:
                // Array of Strings
                int stringarraysize = readLittleEndianBase128Number(bb);
                representation.append("<stringarray size=\"" + stringarraysize + "\">\n");
                for (int j = 0; j < stringarraysize; j++) {
                    int stringlength = (int) bb.get();
                    String s2 = new String(readBytes(bb, stringlength));
                    representation.append("<stringwithlength length=\"" + stringlength + "\">");
                    matcher = CHARS_TO_ENCODE_IN_XML_PATTERN.matcher(s2);
                    malicious = matcher.find();
                    if (malicious) representation.append("<![CDATA[");
                    representation.append(s2);
                    if (malicious) representation.append("]]>");
                    representation.append("</stringwithlength>\n");
                }
                representation.append("</stringarray>\n");
                return representation;
            case 0x16:
                // Container of Objects
                int objectcontainersize = readLittleEndianBase128Number(bb);
                representation.append("<objectarray size=\"" + objectcontainersize + "\">\n");
                for (int i = 0; i < objectcontainersize; i++)
                    representation.append(decodeObjectAsXML(bb));
                representation.append("</objectarray>\n");
                return representation;
            case 0x09:
                // RGBA component
                // TODO: test this case.
                byte rgbabytes[] = new byte[4];
                bb.get(rgbabytes);
                String rgbaashexstring = Hex.encodeHexString(rgbabytes);

                representation.append("<rgba>0x" + rgbaashexstring + "</rgba>");
                return representation;
            case 0x1B:
                // Unit
                // TODO: test this case.
                byte unitbytes[] = new byte[12];
                bb.get(unitbytes);
                String unitashexstring = Hex.encodeHexString(unitbytes);
                representation.append("<unit>0x" + unitashexstring + "</unit>");
                return representation;
            case 0x1F:
                // String reference
                int stringref = readLittleEndianBase128Number(bb);
                representation.append("<stringreference>");
                representation.append(stringref);
                representation.append("</stringreference>\n");
                return representation;
            case 0x18:
                // Control State
                // this logic is based to some degree on https://gist.github.com/Noxwizard/6396665
                // TODO: test this case.
                int controlstatelength = readLittleEndianBase128Number(bb);
                representation.append("<controlstate size=\"" + controlstatelength + "\">\n");
                representation.append(decodeObjectAsXML(bb));
                representation.append(decodeObjectAsXML(bb));
                representation.append("</controlstate>\n");
                return representation;
            case 0x24:
                // UUID
                // TODO: test this case.
                byte uuidbytes[] = new byte[36];
                bb.get(uuidbytes);
                String uuidashexstring = Hex.encodeHexString(uuidbytes);
                representation.append("<uuid>0x" + uuidashexstring + "</uuid>");
                return representation;
            case 0x64:
                return EMPTY_NODE.decoder.apply(bb).orElseThrow(Exception::new);
            case 0x65:
                return EMPTY_STRING.decoder.apply(bb).orElseThrow(Exception::new);
            case 0x66:
                return ZERO.decoder.apply(bb).orElseThrow(Exception::new);
            case 0x67:
                return TRUE.decoder.apply(bb).orElseThrow(Exception::new);
            case 0x68:
                return FALSE.decoder.apply(bb).orElseThrow(Exception::new);
            default:
                throw new Exception("Unsupported object type 0x" + Integer.toHexString(b));
        }
    }

    /**
     * decodes a Base64 encoded byte array into a human readable String, interpreting the Base64
     * decoded data as a tree of ViewState objects.
     *
     * @return a human readable, XML based representation of the ViewState data
     * @throws Exception
     * @param decodedData
     */
    public String decodeAsXML(byte[] decodedData) throws Exception {
        // prepare to parse the base64 decoded data as ViewState data
        ByteBuffer dataBuffer = ByteBuffer.wrap(decodedData);
        byte[] preamble = new byte[2];
        dataBuffer.get(preamble);
        // why are bytes signed in Java??
        if (preamble[0] != -1 || preamble[1] != 0x01) {
            throw new Exception("Invalid Viewstate preamble");
        }

        StringBuilder representation = new StringBuilder("<?xml version=\"1.0\" ?>");
        representation.append("<viewstate>");

        // if the viewstate were encrypted, we would not have been able to decode it at all.
        // because we don't attempt to decrypt it, because we don't have the shared secret key to do
        // so.
        representation.append("<encrypted>false</encrypted>");

        // decode the root object, which contains the remainder of the ViewState
        representation.append(decodeObjectAsXML(dataBuffer));

        // Look at whether the ViewState is protected by a MAC
        // we can tell by looking at how many bytes remain at the end of the data, once
        // the ViewState data has been read out.
        int bytesRemainingToBeRead = dataBuffer.remaining();
        if (bytesRemainingToBeRead > 0) {
            // there are bytes at the end that were not read. This is probably the MAC.
            byte[] dataremaininginbuffer = new byte[bytesRemainingToBeRead];
            dataBuffer.get(dataremaininginbuffer);
            String dataremainderhexencoded = Hex.encodeHexString(dataremaininginbuffer);

            representation.append("<hmac>true</hmac>");
            representation.append(
                    String.format(
                            "<hmactype>%1$s</hmactype>",
                            HMAC_TYPES.getOrDefault(bytesRemainingToBeRead, "HMAC-UNKNOWN")));
            representation.append("<hmaclength>").append(bytesRemainingToBeRead).append("</hmaclength>");
            representation.append("<hmacvalue>0x").append(dataremainderhexencoded).append("</hmacvalue>");
        } else {
            // No unread bytes --> no MAC. The Viewstate can be messed with!! Yee-Ha!
            // NOTE: if this pattern changes, change patternNoHMAC
            representation.append("<hmac>false</hmac>");
        }

        representation.append("</viewstate>");

        // my work here is done.
        return format(representation.toString());
    }

    private static final Map<Integer, String> HMAC_TYPES = new HashMap<>();

    static {
        HMAC_TYPES.put(16, "HMAC-MD5");
        HMAC_TYPES.put(20, "HMAC-SHA0/HMAC-SHA1");
        HMAC_TYPES.put(32, "HMAC-SHA256");
        HMAC_TYPES.put(48, "HMAC-SHA384");
        HMAC_TYPES.put(64, "HMAC-SHA512");
    }

    private static String format(String xml) {
        Transformer transformer;
        try {
            transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "3");
            transformer.setOutputProperty(OutputKeys.METHOD, "html");
            Source source = new StreamSource(new StringReader(xml));
            StreamResult result = new StreamResult(new StringWriter());
            transformer.transform(source, result);
            return "<?xml version=\"1.0\" ?>\n" + result.getWriter().toString();
        } catch (TransformerException e) {
            // Should not happen
            return "";
        }
    }
}
