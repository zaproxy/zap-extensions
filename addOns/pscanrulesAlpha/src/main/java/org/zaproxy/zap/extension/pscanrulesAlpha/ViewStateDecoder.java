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

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Hex;

/**
 * Decodes a ViewState into an XML based format.
 *
 * @author 70pointer@gmail.com
 */
public class ViewStateDecoder {

    // private static final Pattern charsToEncodeInXMLPattern = Pattern.compile("[\\<\\>\\&]+");
    private static final Pattern charsToEncodeInXMLPattern =
            Pattern.compile("[<>\\&]+", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    /** a pattern to use when looking at the output to check if a ViewState is protected by a MAC */
    public static Pattern patternNoHMAC =
            Pattern.compile(
                    "^\\s*\\<hmac\\>false\\</hmac\\>\\s*$",
                    Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    /** how far is the current item indented? */
    private int indentationlevel = 0;

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
     * read a sequence of n bytes from the ByteBuffer and return it as a byte array
     *
     * @param bb the ByteBuffer from which to read n bytes
     * @param n the number of bytes to read
     * @return a byte array containing the read data
     */
    private static byte[] readBytes(ByteBuffer bb, int n) {
        byte[] bytes = new byte[n];
        bb.get(bytes);
        return bytes;
    }

    /**
     * reads a NULL terminated String from the ByteBuffer
     *
     * @param bb the ByteBuffer containing the data to read
     * @return a String (not including the NULL byte)
     */
    private static String readNullTerminatedString(ByteBuffer bb) {
        StringBuffer sb = new StringBuffer();
        byte b = bb.get();
        while (b != 0x00) {
            sb.append((char) b);
            b = bb.get();
        }
        return new String(sb);
    }

    /**
     * gets a Little Endian Base 128 number from the Byte Buffer. This is a form of variable length
     * encoded int value.
     *
     * @param bb the ByteBuffer containing the data
     * @return an integer value
     */
    private static int readLittleEndianBase128Number(ByteBuffer bb) {
        int i = 0;

        int tempbytesread = 0;
        byte b = bb.get();
        tempbytesread++;
        // get the lower 7 bits of b into i
        i = b & 0x7F;
        while ((b & 0x80) > 0) {
            // while the top bit of b is set (the "more" bit)
            // get another byte
            b = bb.get();
            tempbytesread++;
            // left shift the lower 7 bits of b onto the left of the bits of data we have already
            // placed in i
            // i = ((i+1) <<7) | (b& 0x7F);
            i = ((b & 0x7F) << (7 * (tempbytesread - 1))) | i;
        }
        return i;
    }

    /**
     * gets a StringBuffer containing the specified amount of indentation
     *
     * @param n the depth for the indentation
     * @return a StringBuffer containing the specified amount of indentation
     */
    private StringBuffer getIndentation(int n) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < this.indentationlevel; i++) sb.append("   ");
        return sb;
    }

    /**
     * decodes a single (ViewState-specific) object from the ByteBuffer.
     *
     * @param bb the ByteBuffer from which to read the next ViewState object
     * @return a StringBuffer containing the human-readable and machine parseable representation
     *     (XML based)
     * @throws NoMoreDataException
     * @throws Exception
     */
    public StringBuffer decodeObjectAsXML(ByteBuffer bb) throws NoMoreDataException, Exception {
        int b = (int) bb.get();
        StringBuffer representation = new StringBuffer();
        Matcher matcher = null;
        boolean malicious = false;
        switch (b) {
            case 0x02:
                // Unsigned integer
                int intsize = readLittleEndianBase128Number(bb);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<uint32>");
                representation.append(intsize);
                representation.append("</uint32>\n");
                return representation;
            case 0x03:
                // Container of Booleans
                // TODO: test this case.
                int booleancontainersize = readLittleEndianBase128Number(bb);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<booleanarray size=\"" + booleancontainersize + "\">\n");
                this.indentationlevel++;
                for (int i = 0; i < booleancontainersize; i++)
                    representation.append(decodeObjectAsXML(bb));
                this.indentationlevel--;
                representation.append(getIndentation(this.indentationlevel));
                representation.append("</booleanarray>\n");
                return representation;
            case 0x05:
            case 0x1E:
                // String
                int stringsize = readLittleEndianBase128Number(bb);
                String s = new String(readBytes(bb, stringsize));
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<string>");
                matcher = charsToEncodeInXMLPattern.matcher(s);
                malicious = matcher.find();
                if (malicious) representation.append("<![CDATA[");
                representation.append(s);
                if (malicious) representation.append("]]>");
                representation.append("</string>\n");
                return representation;
            case 0x0B:
                // NULL terminated String
                // TODO: test this case.
                String nullterminatedString = readNullTerminatedString(bb);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<stringnullterminated>");
                matcher = charsToEncodeInXMLPattern.matcher(nullterminatedString);
                malicious = matcher.find();
                if (malicious) representation.append("<![CDATA[");
                representation.append(nullterminatedString);
                if (malicious) representation.append("]]>");
                representation.append("</stringnullterminated>\n");
                return representation;
            case 0x0F:
                // Tuple
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<pair>\n");
                this.indentationlevel++;
                representation.append(decodeObjectAsXML(bb));
                representation.append(decodeObjectAsXML(bb));
                this.indentationlevel--;
                representation.append(getIndentation(this.indentationlevel));
                representation.append("</pair>\n");
                return representation;
            case 0x10:
                // Triple
                // TODO: test this case.
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<triple>\n");
                this.indentationlevel++;
                representation.append(decodeObjectAsXML(bb));
                representation.append(decodeObjectAsXML(bb));
                representation.append(decodeObjectAsXML(bb));
                this.indentationlevel--;
                representation.append(getIndentation(this.indentationlevel));
                representation.append("</triple>\n");
                return representation;
            case 0x15:
                // Array of Strings
                int stringarraysize = readLittleEndianBase128Number(bb);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<stringarray size=\"" + stringarraysize + "\">\n");
                this.indentationlevel++;
                for (int j = 0; j < stringarraysize; j++) {
                    int stringlength = (int) bb.get();
                    String s2 = new String(readBytes(bb, stringlength));
                    representation.append(getIndentation(this.indentationlevel + 1));
                    representation.append("<stringwithlength length=\"" + stringlength + "\">");
                    matcher = charsToEncodeInXMLPattern.matcher(s2);
                    malicious = matcher.find();
                    if (malicious) representation.append("<![CDATA[");
                    representation.append(s2);
                    if (malicious) representation.append("]]>");
                    representation.append("</stringwithlength>\n");
                }
                this.indentationlevel--;
                representation.append(getIndentation(this.indentationlevel));
                representation.append("</stringarray>\n");
                return representation;
            case 0x16:
                // Container of Objects
                int objectcontainersize = readLittleEndianBase128Number(bb);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<objectarray size=\"" + objectcontainersize + "\">\n");
                this.indentationlevel++;
                for (int i = 0; i < objectcontainersize; i++)
                    representation.append(decodeObjectAsXML(bb));
                this.indentationlevel--;
                representation.append(getIndentation(this.indentationlevel));
                representation.append("</objectarray>\n");
                return representation;
            case 0x09:
                // RGBA component
                // TODO: test this case.
                byte rgbabytes[] = new byte[4];
                bb.get(rgbabytes);
                String rgbaashexstring = Hex.encodeHexString(rgbabytes);

                representation.append(getIndentation(this.indentationlevel));
                representation.append("<rgba>0x" + rgbaashexstring + "</rgba>");
                return representation;
            case 0x1B:
                // Unit
                // TODO: test this case.
                byte unitbytes[] = new byte[12];
                bb.get(unitbytes);
                String unitashexstring = Hex.encodeHexString(unitbytes);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<unit>0x" + unitashexstring + "</unit>");
                return representation;
            case 0x1F:
                // String reference
                int stringref = readLittleEndianBase128Number(bb);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<stringreference>");
                representation.append(stringref);
                representation.append("</stringreference>\n");
                return representation;
            case 0x18:
                // Control State
                // this logic is based to some degree on https://gist.github.com/Noxwizard/6396665
                // TODO: test this case.
                int controlstatelength = readLittleEndianBase128Number(bb);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<controlstate size=\"" + controlstatelength + "\">\n");
                this.indentationlevel++;
                // for (int i=0; i< controlstatelength; i++)
                representation.append(decodeObjectAsXML(bb));
                representation.append(decodeObjectAsXML(bb));
                this.indentationlevel--;
                representation.append(getIndentation(this.indentationlevel));
                representation.append("</controlstate>\n");
                return representation;
            case 0x24:
                // UUID
                // TODO: test this case.
                byte uuidbytes[] = new byte[36];
                bb.get(uuidbytes);
                String uuidashexstring = Hex.encodeHexString(uuidbytes);
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<uuid>0x" + uuidashexstring + "</uuid>");
                return representation;
            case 0x64:
                // Empty Node
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<emptynode>");
                representation.append("</emptynode>\n");
                return representation;
            case 0x65:
                // Empty String
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<emptystring>");
                representation.append("</emptystring>\n");
                return representation;
            case 0x66:
                // Zero
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<zero>");
                representation.append("</zero>\n");
                return representation;
            case 0x67:
                // True
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<boolean>true</boolean>\n");
                return representation;
            case 0x68:
                // True
                representation.append(getIndentation(this.indentationlevel));
                representation.append("<boolean>false</boolean>\n");
                return representation;
            default:
                throw new Exception("Unsupported object type 0x" + Integer.toHexString(b));
        }
    }

    /**
     * decodes a Base64 encoded byte array into a human readable String, interpreting the Base64
     * decoded data as a tree of ViewState objects.
     *
     * @param base64encoded a byte array containing Base64 encoded ViewState data. Should not
     *     contain superfluous characters at the end, as this breaks the "MAC" detection
     * @return a human readable, XML based representation of the ViewState data
     * @throws Exception
     */
    public String decodeAsXML(byte[] base64encoded) throws Exception {
        byte[] decodeddata = null;
        // String viewstatebase64encoded = new String (base64encoded);
        try {
            decodeddata = Base64.getDecoder().decode(base64encoded);
        } catch (IllegalArgumentException e) {
            throw new Exception("Invalid Base64 data");
        }

        // prepare to parse the base64 decoded data as ViewState data
        ByteBuffer dataBuffer = ByteBuffer.wrap(decodeddata);
        byte[] preamble = new byte[2];
        dataBuffer.get(preamble);
        // why are bytes signed in Java??
        if (preamble[0] != -1 || preamble[1] != 0x01) {
            throw new Exception("Invalid Viewstate preamble");
        }

        StringBuffer representation = new StringBuffer("<?xml version=\"1.0\" ?>\n");
        representation.append("<viewstate>\n");
        this.indentationlevel++;

        // if the viewstate were encrypted, we would not have been able to decode it at all.
        // because we don't attempt to decrypt it, because we don't have the shared secret key to do
        // so.
        representation.append(getIndentation(this.indentationlevel));
        representation.append("<encrypted>false</encrypted>\n");

        // decode the root object, which contains the remainder of the ViewState
        try {
            representation.append(decodeObjectAsXML(dataBuffer));
        } catch (NoMoreDataException nmde) {
            // throw new Exception ("The data does not appear to be valid ViewState Data");
        }

        // Look at whether the ViewState is protected by a MAC
        // we can tell by looking at how many bytes remain at the end of the data, once
        // the ViewState data has been read out.
        int bytesremainingtoberead = dataBuffer.remaining();
        if (bytesremainingtoberead > 0) {
            // there are bytes at the end that were not read. This is probably the MAC.
            byte[] dataremaininginbuffer = new byte[bytesremainingtoberead];
            dataBuffer.get(dataremaininginbuffer);
            String dataremainderhexencoded = Hex.encodeHexString(dataremaininginbuffer);

            representation.append(getIndentation(this.indentationlevel));
            representation.append("<hmac>true</hmac>\n");
            representation.append(getIndentation(this.indentationlevel));
            if (bytesremainingtoberead == 16)
                representation.append("<hmactype>HMAC-MD5</hmactype>\n");
            else if (bytesremainingtoberead == 20)
                representation.append("<hmactype>HMAC-SHA0/HMAC-SHA1</hmactype>\n");
            else if (bytesremainingtoberead == 32)
                representation.append("<hmactype>HMAC-SHA256</hmactype>\n");
            else if (bytesremainingtoberead == 48)
                representation.append("<hmactype>HMAC-SHA384</hmactype>\n");
            else if (bytesremainingtoberead == 64)
                representation.append("<hmactype>HMAC-SHA512</hmactype>\n");
            else representation.append("<hmactype>HMAC-UNKNOWN</hmactype>\n");
            representation.append(getIndentation(this.indentationlevel));
            representation.append("<hmaclength>" + bytesremainingtoberead + "</hmaclength>\n");
            representation.append(getIndentation(this.indentationlevel));
            representation.append("<hmacvalue>0x" + dataremainderhexencoded + "</hmacvalue>\n");
        } else {
            // No unread bytes --> no MAC. The Viewstate can be messed with!! Yee-Ha!
            representation.append(getIndentation(this.indentationlevel));
            // NOTE: if this pattern changes, change patternNoHMAC
            representation.append("<hmac>false</hmac>\n");
        }
        // put in the original ViewState value, in Base64 encoded form.
        // representation.append(getIndentation(this.indentationlevel));
        // representation.append("<viewstatebase64encoded>"+viewstatebase64encoded+"</viewstatebase64encoded>\n");

        this.indentationlevel--;
        representation.append(getIndentation(this.indentationlevel));
        representation.append("</viewstate>\n");

        // my work here is done.
        return new String(representation);
    }
}
