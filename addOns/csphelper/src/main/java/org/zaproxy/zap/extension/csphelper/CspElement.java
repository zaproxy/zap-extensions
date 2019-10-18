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

import java.util.Set;
import java.util.TreeSet;
import org.apache.log4j.Logger;

public class CspElement {

    private CSP csp;
    private String name;
    private boolean enabled;

    private boolean none;
    private boolean all;
    private boolean self;
    private boolean data;
    private boolean mediastream;
    private boolean blob;
    private boolean filesystem;
    private boolean unsafeInline;
    private boolean unsafeEval;
    private boolean strictDynamic;
    private boolean unsafeHashedAttr;
    private boolean noHashNonce;
    private Set<String> extras = new TreeSet<String>();
    private Set<String> hashNonces = new TreeSet<String>();

    private static final Logger LOGGER = Logger.getLogger(CspElement.class);

    public CspElement(CSP csp, String name) {
        this.csp = csp;
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    protected void reset() {
        this.enabled = false;
        this.none = false;
        this.all = false;
        this.self = false;
        this.data = false;
        this.noHashNonce = false;
        this.extras.clear();
        this.hashNonces.clear();
    }

    public boolean getEnabled() {
        return this.enabled;
    }

    public void setEnabled() {
        reset();
        this.enabled = true;
    }

    public void setNone() {
        reset();
        this.none = true;
        this.enabled = true;
    }

    public void setAll() {
        reset();
        this.all = true;
        this.enabled = true;
    }

    public void setSelf() {
        this.none = false;
        this.all = false;
        this.self = true;
        this.enabled = true;
    }

    public void setData() {
        this.none = false;
        this.all = false;
        this.data = true;
        this.enabled = true;
    }

    public void setMediastream() {
        this.none = false;
        this.all = false;
        this.mediastream = true;
        this.enabled = true;
    }

    public void setBlob() {
        this.none = false;
        this.all = false;
        this.blob = true;
        this.enabled = true;
    }

    public void setFilesystem() {
        this.none = false;
        this.all = false;
        this.filesystem = true;
        this.enabled = true;
    }

    public void setUnsafeInline() {
        this.none = false;
        this.all = false;
        this.unsafeInline = true;
        this.noHashNonce = true;
        this.enabled = true;
    }

    public void setUnsafeEval() {
        this.none = false;
        this.all = false;
        this.unsafeEval = true;
        this.enabled = true;
    }

    public void setStrictDynamic() {
        this.none = false;
        this.all = false;
        this.strictDynamic = true;
        this.enabled = true;
    }

    public void setUnsafeHashedAttribute() {
        this.none = false;
        this.all = false;
        this.unsafeHashedAttr = true;
        this.enabled = true;
    }

    public void addUrl(String url) {
        this.none = false;
        this.enabled = true;
        url = url.trim();
        if ((url.startsWith("http://") || url.startsWith("https://"))) {
            url = ExtensionCspHelper.siteFromUrl(url);
        }
        if (url.startsWith(csp.getSite())) {
            LOGGER.debug("element " + name + " addUrl " + url + " isSelf (starts with site)");
            this.setSelf();
        } else if (url.startsWith("//")) {
            // TODO bit simplistic ;)
            LOGGER.debug("element " + name + " addUrl " + url + " isSelf (starts with //)");
            this.setSelf();
        } else if (url.startsWith("data:")) {
            LOGGER.debug("element " + name + " addUrl " + url + " data URI (starts with data:)");
            this.setData();
        } else if (url.startsWith("mediastream:")) {
            LOGGER.debug(
                    "element "
                            + name
                            + " addUrl "
                            + url
                            + " mediasource URI (starts with mediastream:)");
            this.setMediastream();
        } else if (url.startsWith("blob:")) {
            LOGGER.debug(
                    "element " + name + " addUrl " + url + " mediasource URI (starts with blob:)");
            this.setBlob();
        } else if (url.startsWith("filesystem:")) {
            LOGGER.debug(
                    "element "
                            + name
                            + " addUrl "
                            + url
                            + " filesystem URI (starts with filesystem:)");
            this.setFilesystem();
        } else if ((url.startsWith("http://") || url.startsWith("https://"))
                && url != csp.getSite()) {
            LOGGER.debug("element " + name + " addUrl " + url + " external URI (url != csp site)");
            this.addExtra(url);
        } else {
            LOGGER.debug("element " + name + " addUrl " + url + " isSelf (default)");
            this.setSelf();
        }
    }

    public void addExtra(String extra) {
        this.none = false;
        this.enabled = true;
        this.extras.add(extra);
    }

    public void addHashNonce(String hashNonce) {
        this.none = false;
        this.enabled = true;
        this.hashNonces.add(hashNonce);
    }

    public String generate() {
        LOGGER.debug("Element " + name + " enabled? " + this.enabled);
        if (!this.enabled) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        generate(sb);
        return sb.toString();
    }

    public void generate(StringBuilder sb) {
        LOGGER.debug("Element " + name + " enabled? " + this.enabled);
        if (!this.enabled) {
            return;
        }

        sb.append(name);

        if (this.none) {
            sb.append(" 'none'");
        } else if (this.all) {
            sb.append(" *");
        } else {
            if (this.self) {
                sb.append(" 'self'");
            }
            if (this.data) {
                sb.append(" data:");
            }
            if (this.blob) {
                sb.append(" blob:");
            }
            if (this.mediastream) {
                sb.append(" mediastream:");
            }
            if (this.filesystem) {
                sb.append(" filesystem:");
            }
            if (this.unsafeInline) {
                sb.append(" 'unsafe-inline'");
            }
            if (this.unsafeEval) {
                sb.append(" 'unsafe-eval'");
            }
            if (this.strictDynamic) {
                sb.append(" 'strict-dynamic'");
            }
            if (this.unsafeHashedAttr) {
                sb.append(" 'unsafe-hashed-attribute'");
            }
            for (String extra : extras) {
                sb.append(' ');
                sb.append(extra);
            }
            if (!this.noHashNonce) {
                for (String hashNonce : hashNonces) {
                    sb.append(' ');
                    sb.append(hashNonce);
                }
            }
        }
        sb.append("; ");
    }
}
