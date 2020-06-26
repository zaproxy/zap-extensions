/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ViewstateScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanrules.viewstate.";
    private static final int PLUGIN_ID = 10032;

    private static Pattern hiddenFieldPattern = Pattern.compile("__.*");

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Nothing to do on send
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        Map<String, StartTag> hiddenFields = getHiddenFields(source);
        if (hiddenFields.isEmpty()) return;

        Viewstate v = extractViewstate(hiddenFields);

        // If the viewstate is invalid, we stop here
        // TODO: in the future, we might want to differentiate an encrypted viewstate and still
        // consider it as valid.
        if (!v.isValid()) return;

        if (!v.hasMACtest1() || !v.hasMACtest2())
            if (!v.hasMACtest1() && !v.hasMACtest2()) alertNoMACforSure(msg, id);
            else alertNoMACUnsure(msg, id);

        if (!v.isLatestAspNetVersion()) alertOldAspVersion(msg, id);

        List<ViewstateAnalyzerResult> listOfMatches = ViewstateAnalyzer.getSearchResults(v, this);
        for (ViewstateAnalyzerResult var : listOfMatches) {
            if (var.hasResults()) alertViewstateAnalyzerResult(msg, id, var);
        }

        if (v.isSplit()) alertSplitViewstate(msg, id);
    }

    private void alertViewstateAnalyzerResult(
            HttpMessage msg, int id, ViewstateAnalyzerResult var) {
        newAlert()
                .setName(var.pattern.getAlertHeader())
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(var.pattern.getAlertDescription())
                .setOtherInfo(var.getResultExtract().toString())
                .setSolution(getSolution())
                .setCweId(16) // CWE Id 16 - Configuration
                .setWascId(14) // WASC Id - Server Misconfiguration
                .raise();
    }

    private void alertOldAspVersion(HttpMessage msg, int id) {
        newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX + "oldver.name"))
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "oldver.desc"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "oldver.soln"))
                .setCweId(16) // CWE Id 16 - Configuration
                .setWascId(14) // WASC Id - Server Misconfiguration
                .raise();
    }

    // TODO: see if this alert triggers too often, as the detection rule is far from being robust
    // for the moment
    private void alertNoMACUnsure(HttpMessage msg, int id) {
        newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX + "nomac.unsure.name"))
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "nomac.unsure.desc"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "nomac.unsure.soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "nomac.unsure.refs"))
                .setCweId(642) // CWE Id 642 - External Control of Critical State Data
                .setWascId(14) // WASC Id - Server Misconfiguration
                .raise();
    }

    private void alertNoMACforSure(HttpMessage msg, int id) {
        newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX + "nomac.sure.name"))
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "nomac.sure.desc"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "nomac.sure.soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "nomac.sure.refs"))
                .setCweId(642) // CWE Id 642 - External Control of Critical State Data
                .setWascId(14) // WASC Id - Server Misconfiguration
                .raise();
    }

    private void alertSplitViewstate(HttpMessage msg, int id) {
        newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX + "split.name"))
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "split.desc"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "split.soln"))
                .setCweId(16) // CWE Id 16 - Configuration
                .setWascId(14) // WASC Id - Server Misconfiguration
                .raise();
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private Map<String, StartTag> getHiddenFields(Source source) {
        List<StartTag> result = source.getAllStartTags("input");

        // Searching for name only tags only makes sense for Asp.Net 1.1 websites
        // TODO: Enhance this ugly code
        List<StartTag> hiddenNames = source.getAllStartTags("name", hiddenFieldPattern);
        for (StartTag st : hiddenNames) if (!result.contains(st)) result.add(st);

        // Creating a key:StartTag map based on the previous results
        Map<String, StartTag> stMap = new TreeMap<>();
        for (StartTag st : result) {
            // TODO: fix exception occurring here (st == null?)
            String name =
                    (st.getAttributeValue("id") == null)
                            ? st.getAttributeValue("name")
                            : st.getAttributeValue("id");

            // <input type="hidden" /> will generate a null pointer exception otherwise
            if (name != null) stMap.put(name, st);
        }
        return stMap;
    }

    // TODO: see how to manage exceptions in this class...
    private Viewstate extractViewstate(Map<String, StartTag> lstHiddenFields) {
        // If the viewstate isn't split, we simply return the Viewstate object based on the field
        if (!lstHiddenFields.containsKey("__VIEWSTATEFIELDCOUNT"))
            return new Viewstate(lstHiddenFields.get("__VIEWSTATE"));

        // Otherwise we concatenate manually the viewstate
        StringBuilder tmpValue = new StringBuilder();

        tmpValue.append(lstHiddenFields.get("__VIEWSTATE").getAttributeValue("value"));

        int max =
                Integer.parseInt(
                        lstHiddenFields.get("__VIEWSTATEFIELDCOUNT").getAttributeValue("value"));
        for (int i = 1; i < max; i++) {
            tmpValue.append(lstHiddenFields.get("__VIEWSTATE" + i).getAttributeValue("value"));
        }

        return new Viewstate(tmpValue.toString(), true);
    }

    private class ViewstateAnalyzerResult {

        private ViewstateAnalyzerPattern pattern;
        private Set<String> resultExtract = new HashSet<>();

        public ViewstateAnalyzerResult(ViewstateAnalyzerPattern vap) {
            this.pattern = vap;
        }

        public void addResults(String s) {
            this.resultExtract.add(s);
        }

        public Set<String> getResultExtract() {
            return this.resultExtract;
        }

        public boolean hasResults() {
            return !this.resultExtract.isEmpty();
        }
    }

    // TODO: enhance this class with searches for e.g. passwords, ODBC strings, etc
    private static enum ViewstateAnalyzerPattern {
        EMAIL(
                Pattern.compile(
                        "[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}", Pattern.CASE_INSENSITIVE),
                Constant.messages.getString(MESSAGE_PREFIX + "content.email.name"),
                Constant.messages.getString(MESSAGE_PREFIX + "content.email.desc"),
                Constant.messages.getString(MESSAGE_PREFIX + "content.email.pattern.source")),

        // TODO: once the viewstate parser is implemented, filter out all the version numbers of the
        // serialized objects which also trigger this filter
        // Example: Microsoft.SharePoint.WebControls.SPControlMode, Microsoft.SharePoint,
        // Version=12.0.0.0, Culture=neutral,
        // TODO: maybe replace this regex by a tigher rule, avoiding detecting 999.999.999.999
        IPADDRESS(
                Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"),
                Constant.messages.getString(MESSAGE_PREFIX + "content.ip.name"),
                Constant.messages.getString(MESSAGE_PREFIX + "content.ip.desc"),
                Constant.messages.getString(MESSAGE_PREFIX + "content.ip.pattern.source"));

        ViewstateAnalyzerPattern(
                Pattern p, String alertHeader, String alertDescription, String sourceRegex) {
            this.pattern = p;
            this.alertHeader = alertHeader;
            this.alertDescription = alertDescription;
            this.sourceRegex = sourceRegex;
        }

        private Pattern pattern;
        private String alertHeader;
        private String alertDescription;
        private String sourceRegex;

        public Pattern getPattern() {
            return this.pattern;
        }

        public String getAlertDescription() {
            return this.alertDescription;
        }

        public String getAlertHeader() {
            return this.alertHeader;
        }
    }

    private static class ViewstateAnalyzer {

        public static List<ViewstateAnalyzerResult> getSearchResults(
                Viewstate v, ViewstateScanRule s) {
            List<ViewstateAnalyzerResult> result = new ArrayList<>();

            for (ViewstateAnalyzerPattern vap : ViewstateAnalyzerPattern.values()) {
                Matcher m = vap.getPattern().matcher(v.decodedValue);
                ViewstateAnalyzerResult var = s.new ViewstateAnalyzerResult(vap);

                while (m.find()) {
                    // TODO: if we find the text in the viewstate, we also need to check it isn't
                    // already in clear text in the page
                    var.addResults(m.group());
                }

                result.add(var);
            }

            return result;
        }
    }

    public enum ViewstateVersion {
        ASPNET1(1f, 1.1f, false),
        ASPNET2(2f, 4f, true),
        UNKNOWN(-1f, -1f, false);

        private final float minVersion;
        private final float maxVersion;
        private final boolean isLatest;

        ViewstateVersion(float minVersion, float maxVersion, boolean isLatest) {
            this.minVersion = minVersion;
            this.maxVersion = maxVersion;
            this.isLatest = isLatest;
        }

        public boolean isLatest() {
            return this.isLatest;
        }
    }

    // inner class Viewstate
    private class Viewstate {

        private String base64Value;
        private String decodedValue;
        private boolean isValid = false;
        private boolean isSplit;
        private ViewstateVersion version;

        public Viewstate(StartTag s) {
            this(s, false);
        }

        public Viewstate(StartTag s, boolean wasSplit) {
            if (s != null) {
                this.isSplit = wasSplit;
                this.base64Value = s.getAttributeValue("value");
                try {
                    this.decodedValue =
                            new String(Base64.decode(this.base64Value), Charset.forName("UTF-8"));
                    this.isValid = true;
                    this.setVersion();
                } catch (IllegalArgumentException | IOException e) {
                    // Incorrect Base64 value.
                }
            }
        }

        // TODO: tidy up these two constructors
        // TODO: check if splitting was possible with ASP.NET 1.1
        public Viewstate(String s, boolean wasSplit) {
            if (s != null) {
                this.isSplit = wasSplit;
                this.base64Value = s;
                try {
                    this.decodedValue =
                            new String(Base64.decode(this.base64Value), Charset.forName("UTF-8"));
                    this.isValid = true;
                    this.setVersion();
                } catch (IllegalArgumentException | IOException e) {
                    // Incorrect Base64 value.
                }
            }
        }

        public boolean isValid() {
            return this.isValid && (this.getVersion() != ViewstateVersion.UNKNOWN);
        }

        public boolean isSplit() {
            return this.isSplit;
        }

        // TODO: enhance this code, as it WILL fail at least in the following cases:
        //			- MAC is set to another value than the default (e.g. bigger or smaller than 20
        // characters)
        //			- some ASP.NET 3.5 stuff, especially linked with SharePoint, don't seem to use 'd' as
        // null character
        //			- some Viewstates don't have their last 2 objects set to null

        // TODO: replace this bool by a more fuzzy indicator
        public boolean hasMACtest1() {
            int l = this.decodedValue.length();
            // By default, the MAC is 20 characters long
            String lastCharsBeforeMac = this.decodedValue.substring(l - 22, l - 20);

            if (this.version.equals(ViewstateVersion.ASPNET2))
                return lastCharsBeforeMac.equals("dd");

            if (this.version.equals(ViewstateVersion.ASPNET1))
                return lastCharsBeforeMac.equals(">>");

            return true;
        }

        public boolean hasMACtest2() {
            int l = this.decodedValue.length();
            // By default, the MAC is 20 characters long
            String lastCharsBeforeMac = this.decodedValue.substring(l - 2);

            if (this.version.equals(ViewstateVersion.ASPNET2))
                return !lastCharsBeforeMac.equals("dd");

            if (this.version.equals(ViewstateVersion.ASPNET1))
                return !lastCharsBeforeMac.equals(">>");

            return true;
        }

        public String getDecodedValue() {
            return this.decodedValue;
        }

        public boolean isLatestAspNetVersion() {
            return this.getVersion().isLatest();
        }

        public ViewstateVersion getVersion() {
            return this.version;
        }

        private void setVersion() {
            this.version = ViewstateVersion.UNKNOWN;

            if (this.base64Value.startsWith("/w")) this.version = ViewstateVersion.ASPNET2;

            if (this.base64Value.startsWith("dD")) this.version = ViewstateVersion.ASPNET1;
        }

        /* TODO once we have good Viewstate 1 & 2 parsers */
        public Object[] getObjectTree() throws Exception {
            throw new Exception("Not implemented (yet)");
        }

        public Object[] getStateBagTree() throws Exception {
            throw new Exception("Not implemented (yet)");
        }

        public Object[] getSerializedComponentsTree() throws Exception {
            throw new Exception("Not implemented (yet)");
        }
    }
}
