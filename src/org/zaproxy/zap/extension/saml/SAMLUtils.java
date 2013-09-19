package org.zaproxy.zap.extension.saml;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

/**
 * Contains some frequent methods related to decoding and encoding SAML messages
 */
public class SAMLUtils {
    private static final int MAX_INFLATED_SIZE = 5000;

    protected static final Logger log = Logger.getLogger(SAMLUtils.class);
    /**
     * Private constructor, because this class is and Util class and the methods are static
     */
    private SAMLUtils(){
    }

    /**
     * Base 64 decode a given string and gives the decoded data as a byte array
     * @param message The String to base 64 decode
     * @return Byte array of the decoded string
     * @throws SAMLException
     */
    public static byte[] b64Decode(String message) throws SAMLException{
        try {
            return Base64.decode(message);
        } catch (IOException e) {
            throw new SAMLException("Base 64 Decode of failed for message: \n"+message,e);
        }
    }

    /**
     * Base 64 encode the given byte array and gives the encoded string
     * @param data The data to encode
     * @return Encoded string
     */
    public static String b64Encode(byte[] data){
        return Base64.encodeBytes(data);
    }

    /**
     * Inflate a message (that had been deflated) and gets the original message
     * @param data Byte array of deflated data that need to be inflated
     * @return Original message after inflation
     * @throws SAMLException
     */
    public static String inflateMessage(byte[] data) throws SAMLException {
        try {
            Inflater inflater = new Inflater(true);
            inflater.setInput(data);
            byte[] xmlMessageBytes = new byte[MAX_INFLATED_SIZE];
            int resultLength = inflater.inflate(xmlMessageBytes);

            if (!inflater.finished()) {
                throw new SAMLException("Out of space allocated for inflated data");
            }

            inflater.end();

            return new String(xmlMessageBytes, 0, resultLength,
                    "UTF-8");
        } catch (DataFormatException e) {
            throw new SAMLException("Invalid data format",e);
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException("Inflated data is not in valid encoding format",e);
        }
    }

    /**
     * Deflate a message to be send over a preferred binding
     * @param message Message to be deflated
     * @return The deflated message as a byte array
     */
    public static byte[] deflateMessage(String message) throws SAMLException {
        try {
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream =
                    new DeflaterOutputStream(byteArrayOutputStream,
                            deflater);

            deflaterOutputStream.write(message.getBytes());
            deflaterOutputStream.close();

            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
           throw new SAMLException("Message Deflation failed",e);
        }
    }

    /**
     * Check whether the httpMessage has a saml message in its parameters
     * @param message The HttpMessage to be checked for
     * @return whether the message has got a saml message within it
     */
    public static boolean hasSAMLMessage(HttpMessage message){
        for (HtmlParameter parameter : message.getUrlParams()) {
            if(parameter.getName().equals("SAMLRequest") && isNonEmptyValue(parameter.getValue())){
                return true;
            }
            if(parameter.getName().equals("SAMLResponse") && isNonEmptyValue(parameter.getValue())){
                return true;
            }
        }
        for (HtmlParameter parameter : message.getFormParams()) {
            if(parameter.getName().equals("SAMLRequest") && isNonEmptyValue(parameter.getValue())){
                return true;
            }
            if(parameter.getName().equals("SAMLResponse") && isNonEmptyValue(parameter.getValue())){
                return true;
            }
        }
        return false;
    }

    private static boolean isNonEmptyValue(String param){
        return param != null && !"".equals(param);
    }

    /**
     * Decode the SAML messages based on the binding used
     * @param val the SAML message to decode
     * @param binding The binding used
     * @return The decoded SAML message if success, or the original string if failed
     */
    public static String extractSAMLMessage(String val, Binding binding){
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
