/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.httpsinfo;

import java.util.ArrayList;
import java.util.List;


public class CertificateFound {

    private Certification certification;
    private List<CipherSuite> cipherSuites;

    public CertificateFound(Certification certification) {
        this.certification = certification;
        this.cipherSuites = new ArrayList<>();
    }

    public Certification getCertification() {
        return certification;
    }

    public void addCipherSuites(CipherSuite cipherSuite) {
        cipherSuites.add(cipherSuite);
    }

    public String getCipherSuite() {
        StringBuilder content =  new StringBuilder();

        for (CipherSuite cipherSuite : cipherSuites) {
            content.append(cipherSuite.getSuiteName());
            content.append('(');
            content.append(cipherSuite.getStrengthEvaluation());
            content.append(',');
            content.append(cipherSuite.getHandshakeProtocol());
            content.append(')');
            content.append('\n');
        }

        return content.toString();
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

}
