/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.csphelper;

public class ReferrerElement extends CspElement {

    public ReferrerElement(CSP csp, String name) {
        super(csp, name);
    }

    public void setNoReferrer() {
        this.reset();
        this.addExtra("no-referrer");
    }

    public void setNoReferrerWhenDowngrade() {
        this.reset();
        this.addExtra("no-referrer-when-downgrade");
    }

    public void setSameOrigin() {
        this.reset();
        this.addExtra("same-origin");
    }

    public void setOrigin() {
        this.reset();
        this.addExtra("origin");
    }

    public void setOriginWhenCrossOrigin() {
        this.reset();
        this.addExtra("origin-when-cross-origin");
    }

    public void setUnsafeUrl() {
        this.reset();
        this.addExtra("unsafe-url");
    }
}
