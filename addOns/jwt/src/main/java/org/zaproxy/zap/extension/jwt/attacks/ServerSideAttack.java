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
package org.zaproxy.zap.extension.jwt.attacks;

import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.jwt.JWTActiveScanner;
import org.zaproxy.zap.extension.jwt.JWTHolder;

/**
 * This class is used to find vulnerabilities in server side implementation of JWT.
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class ServerSideAttack {
    private JWTActiveScanner jwtActiveScanner;
    private String param;
    private String paramValue;
    private HttpMessage msg;
    private JWTHolder jwtHolder;
    private static final List<JWTAttack> JWTATTACKS =
            Arrays.asList(
                    new HeaderAttack(),
                    new PayloadAttack(),
                    new SignatureAttack(),
                    new MiscAttack());

    /**
     * @param jwtHolder Parsed JWT Token
     * @param jwtActiveScanner instance of {@link JWTActiveScanner}
     * @param msg original Http Message
     * @param param parameter having JWT token
     * @param paramValue original parameter value
     */
    public ServerSideAttack(
            JWTHolder jwtHolder,
            JWTActiveScanner jwtActiveScanner,
            String param,
            HttpMessage msg,
            String paramValue) {
        this.jwtHolder = jwtHolder;
        this.jwtActiveScanner = jwtActiveScanner;
        this.param = param;
        this.msg = msg;
        this.paramValue = paramValue;
    }

    public JWTActiveScanner getJwtActiveScanner() {
        return jwtActiveScanner;
    }

    public String getParam() {
        return param;
    }

    public String getParamValue() {
        return paramValue;
    }

    public HttpMessage getMsg() {
        return msg;
    }

    public JWTHolder getJwtHolder() {
        return jwtHolder;
    }

    public boolean execute() {
        for (JWTAttack jwtAttack : JWTATTACKS) {
            if (jwtActiveScanner.isStop()) {
                return false;
            } else {
                if (jwtAttack.executeAttack(this)) {
                    return true;
                }
            }
        }
        return false;
    }
}
