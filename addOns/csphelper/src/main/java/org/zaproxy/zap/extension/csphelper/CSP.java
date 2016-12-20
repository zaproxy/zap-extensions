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

import java.lang.reflect.Field;
import java.util.ArrayList;
import org.apache.log4j.Logger;

public class CSP {

    private String site;
    private boolean init = false;
    private boolean enabled = true;
    private CspElement baseUri = new CspElement(this, "base-uri");
    private CspElement defaultSource = new CspElement(this, "default-src");
    private CspElement scriptSource = new CspElement(this, "script-src");
    private CspElement styleSource = new CspElement(this, "style-src");
    private CspElement imageSource = new CspElement(this, "img-src");
    private CspElement fontSource = new CspElement(this, "font-src");
    private CspElement connectSource = new CspElement(this, "connect-src");
    private CspElement mediaSource = new CspElement(this, "media-src");
    private CspElement objectSource = new CspElement(this, "object-src");
    private CspElement childSource = new CspElement(this, "child-src");
    private CspElement frameSource = new CspElement(this, "frame-src");
    private CspElement workerSource = new CspElement(this, "worker-src");
    private CspElement manifestSource = new CspElement(this, "manifest-src");
    private CspElement frameAncestors = new CspElement(this, "frame-ancestors");
    private CspElement formAction = new CspElement(this, "form-action");
    private CspElement upgradeInsecure = new CspElement(this, "upgrade-insecure-requests");
    private CspElement blockMixedContent = new CspElement(this, "block-all-mixed-content");
    private CspElement disownOpener = new CspElement(this, "disown-opener");
    private RequireSriForElement requireSriFor = new RequireSriForElement(this, "require-sri-for");
    private SandboxElement sandbox = new SandboxElement(this, "sandbox");
    private ReflectedXssElement reflectedXss = new ReflectedXssElement(this, "reflected-xss");
    private CspElement pluginTypes = new CspElement(this, "plugin-types");
    private ReferrerElement referrer = new ReferrerElement(this, "referrer");
    private CspElement reportOnly = new CspElement(this, "report-only");
    private CspElement reportTo = new CspElement(this, "report-to");
    private String reportUri;

    private static final Logger LOGGER = Logger.getLogger(CSP.class);

    public CSP(String site) {
        this.site = site;
        // Defaults
        defaultSource.setNone();
        reflectedXss.setBlock();
        referrer.setNoReferrer();
        frameAncestors.setNone();
        scriptSource.setSelf();
        imageSource.setSelf();
        // requireSriFor.setScript(); - Not supported FF 49.0
        // requireSriFor.setStyle(); - Not supported FF 49.0
        // sandbox.setEnabled(); - Not supported FF 49.0
        // reportOnly.setEnabled(); - Not supported FF 49.0
        if (site.startsWith("https://")) {
            upgradeInsecure.setEnabled();
            blockMixedContent.setEnabled();
        }
    }

    public String generate() {
        StringBuilder sb = new StringBuilder();
        generate(sb);
        return sb.toString();
    }

    public String[] getDirectives() {
        ArrayList<String> dirs = new ArrayList<String>();
        try {
            Class<?> csp = Class.forName(this.getClass().getName());
            Field[] fields = csp.getDeclaredFields();
            for (Field f : fields) {
                if (f.getType() == CspElement.class) {
                    CspElement cspEl = (CspElement) f.get(this);
                    dirs.add(cspEl.getName());
                }
            }
        } catch (Exception e) {
            LOGGER.error("Exception getting class fields: " + e.getMessage());
            LOGGER.error(e.getStackTrace());
        }
        return dirs.toArray(new String[0]);
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enable) {
        this.enabled = enable;
    }

    public boolean isInitialised() {
        return this.init;
    }

    public void setInitialised(boolean initialised) {
        this.init = initialised;
    }

    public void generate(StringBuilder sb) {
        baseUri.generate(sb);
        defaultSource.generate(sb);
        scriptSource.generate(sb);
        styleSource.generate(sb);
        imageSource.generate(sb);
        fontSource.generate(sb);
        connectSource.generate(sb);
        mediaSource.generate(sb);
        objectSource.generate(sb);
        childSource.generate(sb);
        frameSource.generate(sb);
        workerSource.generate(sb);
        manifestSource.generate(sb);
        frameAncestors.generate(sb);
        formAction.generate(sb);
        upgradeInsecure.generate(sb);
        blockMixedContent.generate(sb);
        disownOpener.generate(sb);
        requireSriFor.generate(sb);
        sandbox.generate(sb);
        reflectedXss.generate(sb);
        pluginTypes.generate(sb);
        referrer.generate(sb);
        reportOnly.generate(sb);
        reportTo.generate(sb);

        LOGGER.debug("Report URI " + reportUri);
        if (reportUri != null && reportUri.length() > 0) {
            sb.append("report-uri ");
            sb.append(this.reportUri);
            sb.append(';');
        }
    }

    public String getSite() {
        return site;
    }

    public CspElement getDefaultSource() {
        return defaultSource;
    }

    public CspElement getScriptSource() {
        return scriptSource;
    }

    public CspElement getStyleSource() {
        return styleSource;
    }

    public CspElement getImageSource() {
        return imageSource;
    }

    public CspElement getFontSource() {
        return fontSource;
    }

    public CspElement getConnectSource() {
        return connectSource;
    }

    public CspElement getMediaSource() {
        return mediaSource;
    }

    public CspElement getObjectSource() {
        return objectSource;
    }

    public CspElement getChildSource() {
        return childSource;
    }

    public CspElement getFrameSource() {
        return frameSource;
    }

    public CspElement getWorkerSource() {
        return workerSource;
    }

    public CspElement getManifestSource() {
        return manifestSource;
    }

    public CspElement getFrameAncestors() {
        return frameAncestors;
    }

    public CspElement getFormAction() {
        return formAction;
    }

    public CspElement getUpgradeInsecureRequests() {
        return upgradeInsecure;
    }

    public CspElement getBlockedMixedContent() {
        return blockMixedContent;
    }

    public CspElement getDisownOpener() {
        return disownOpener;
    }

    public CspElement getRequireSriFor() {
        return requireSriFor;
    }

    public CspElement getSandbox() {
        return sandbox;
    }

    public CspElement getReflectedXss() {
        return reflectedXss;
    }

    public CspElement getPluginTypes() {
        return pluginTypes;
    }

    public CspElement getReferrer() {
        return referrer;
    }

    public CspElement getReportOnly() {
        return reportOnly;
    }

    public CspElement getReportTo() {
        return reportTo;
    }

    public CspElement getBaseUri() {
        return baseUri;
    }

    public void setReportUrl(String uri) {
        this.reportUri = uri;
    }

    public CspElement getSource(String name) {
        if (defaultSource.getName().equals(name)) {
            return defaultSource;
        }
        if (scriptSource.getName().equals(name)) {
            return scriptSource;
        }
        if (styleSource.getName().equals(name)) {
            return styleSource;
        }
        if (imageSource.getName().equals(name)) {
            return imageSource;
        }
        if (fontSource.getName().equals(name)) {
            return fontSource;
        }
        if (connectSource.getName().equals(name)) {
            return connectSource;
        }
        if (mediaSource.getName().equals(name)) {
            return mediaSource;
        }
        if (objectSource.getName().equals(name)) {
            return objectSource;
        }
        if (childSource.getName().equals(name)) {
            return childSource;
        }
        if (frameSource.getName().equals(name)) {
            return frameSource;
        }
        if (workerSource.getName().equals(name)) {
            return workerSource;
        }
        if (manifestSource.getName().equals(name)) {
            return manifestSource;
        }

        return null;
    }
}
