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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Port for the Watcher passive scanner (http://websecuritytool.codeplex.com/) rule {@code
 * CasabaSecurity.Web.Watcher.Checks.CheckPasvUserControlledCookie}
 */
public class UserControlledCookieScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanbeta.usercontrolledcookie.";

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // do nothing
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        List<String> cookies = msg.getResponseHeader().getHeaderValues(HttpHeader.SET_COOKIE);
        if (cookies.isEmpty()) {
            return;
        }

        Set<HtmlParameter> params = new TreeSet<>(msg.getFormParams());
        params.addAll(msg.getUrlParams());
        if (params.isEmpty()) {
            return;
        }

        for (String cookie : cookies) {
            cookie = decodeCookie(cookie, msg.getResponseHeader().getCharset());
            if (cookie == null) {
                continue;
            }

            // Now we have a cookie.  Parse it out into an array.
            // I'm doing this to avoid false positives.  By parsing
            // the cookie at each delimiter, I'm checking to see that
            // we can match user-input directly.  Otherwise we'd find
            // all the cases where the cookie simply 'contained' user input,
            // which leads to many false positives.
            // For example, if user input was 'number=20' and the cookie was
            // value=82384920 then we don't want to match.  I want precise
            // matches such as value=20.
            //
            // Common delimiters in cookies.  E.g. name=value;name2=v1|v2|v3
            String[] cookieSplit = cookie.split("[;=|]");
            for (String cookiePart : cookieSplit) {
                checkUserControllableCookieHeaderValue(msg, id, params, cookiePart, cookie);
            }
        }
    }

    // Cookies are commonly URL encoded, maybe other encodings.
    // TODO: apply other decodings?  htmlDecode, etc.
    private String decodeCookie(String cookie, String charset) {
        if (charset != null) {
            try {
                return URLDecoder.decode(cookie, charset);
            } catch (UnsupportedEncodingException e) {
                // try other possible charsets
            }
        }

        // if charset is not defined for response, or is defined incorrectly,
        // try standard charsets

        Charset[] possibleCharsets = {
            StandardCharsets.ISO_8859_1,
            StandardCharsets.US_ASCII,
            StandardCharsets.UTF_16,
            StandardCharsets.UTF_16BE,
            StandardCharsets.UTF_16LE,
            StandardCharsets.UTF_8
        };

        for (Charset possibleCharset : possibleCharsets) {
            try {
                return URLDecoder.decode(cookie, possibleCharset.name());
            } catch (UnsupportedEncodingException e) {
            }
        }

        return null;
    }

    private void checkUserControllableCookieHeaderValue(
            HttpMessage msg, int id, Set<HtmlParameter> params, String cookiePart, String cookie) {
        if (cookie.length() == 0) {
            return;
        }

        for (HtmlParameter param : params) {
            // False Positive Reduction
            // Need to ignore parameters equal to empty value (e.g. name= )
            // otherwise we'll wind up with false positives when cookie
            // values are also set to empty.
            //
            // False Positive Reduction
            // Ignore values not greater than 1 character long.  It seems to
            // be common that value=0 and value=/ type stuff raise a false
            // positive.
            if (param.getValue() != null
                    && param.getValue().length() > 1
                    && param.getValue().equals(cookiePart)) {
                raiseAlert(msg, id, param, cookie);
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, HtmlParameter param, String cookie) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescriptionMessage())
                .setParam(param.getName())
                .setOtherInfo(getExtraInfoMessage(msg, param, cookie))
                .setSolution(getSolutionMessage())
                .setReference(getReferenceMessage())
                .setCweId(20) // CWE-20: Improper Input Validation
                .setWascId(20) // WASC-20: Improper Input Handling
                .raise();
    }

    @Override
    public int getPluginId() {
        return 10029;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    /*
     * Rule-associated messages
     */

    private String getDescriptionMessage() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolutionMessage() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReferenceMessage() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private String getExtraInfoMessage(HttpMessage msg, HtmlParameter param, String cookie) {
        String introMessage = "";
        if ("GET".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
            introMessage = Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.get");
        } else if ("POST".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
            introMessage = Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.post");
        }
        return Constant.messages.getString(
                MESSAGE_PREFIX + "extrainfo",
                introMessage,
                msg.getRequestHeader().getURI().toString(),
                cookie,
                param.getName(),
                param.getValue());
    }
}
