/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.testutils.NanoServerHandler;

/**
 * General Null Byte Vulnerable Server Handler
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class NullByteVulnerableServerHandler extends NanoServerHandler {

    private String param;
    private Tech tech;

    private static final String GENERIC_VULN_RESPONSE_NIX =
            "<!DOCTYPE html>\n"
                    + "<html>"
                    + "<head>"
                    + "<title>Page Title</title>"
                    + "</head>"
                    + "<body>"
                    + "<p>root:x:0:0:root:/root:/bin/bash\n"
                    + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    + "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                    + "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                    + "sync:x:4:65534:sync:/bin:/bin/sync\n"
                    + "</p>"
                    + "</body>"
                    + "</html>";

    private static final String GENERIC_VULN_RESPONSE_WIN =
            "<!DOCTYPE html>\n"
                    + "<html>"
                    + "<head>"
                    + "<title>Page Title</title>"
                    + "</head>"
                    + "<body>"
                    + "<p>[drivers]\n"
                    + "wave=mmdrv.dll\n"
                    + "timer=timer.drv\n"
                    + "[fonts]\n"
                    + "</p>"
                    + "</body>"
                    + "</html>";

    public NullByteVulnerableServerHandler(String name, String param, Tech tech) {
        super(name);
        this.param = param;
        this.tech = tech;
    }

    protected String getContent(IHTTPSession session) {
        String value = getFirstParamValue(session, this.param);
        if (value.contains(NULL_BYTE_CHARACTER)) {
            return this.tech.equals(Tech.Linux) || this.tech.equals(Tech.MacOS)
                    ? GENERIC_VULN_RESPONSE_NIX
                    : GENERIC_VULN_RESPONSE_WIN;
        } else {
            return "<html></html>";
        }
    }

    @Override
    protected Response serve(IHTTPSession session) {
        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, getContent(session));
    }
}
