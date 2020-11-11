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
package org.zaproxy.zap.extension.viewstate.zap.utils;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;
import org.apache.log4j.Logger;

public class ASPViewState extends ViewState {

    private static Logger logger = Logger.getLogger(ASPViewState.class);
    public static final String KEY = "ASP";

    private boolean isValid = true;
    private static boolean isSplit = false;
    private static int numSplitFields = 0;
    private ViewstateVersion version;
    private static Pattern hiddenFieldPattern = Pattern.compile("__.*");

    public ASPViewState(String base64, String name) {
        super(base64, KEY, name);
        if (this.value != null) {
            this.setVersion();
        }
    }

    public static ASPViewState getFromSource(Source source) {
        return new ASPViewState(extractViewstate(getHiddenFields(source)), "__VIEWSTATE");
    }

    private static Map<String, StartTag> getHiddenFields(Source source) {
        List<StartTag> result = source.getAllStartTags("input");

        // Searching for name only tags only makes sense for Asp.Net 1.1
        // websites
        List<StartTag> hiddenNames = source.getAllStartTags("name", hiddenFieldPattern);
        for (StartTag st : hiddenNames) {
            if (!result.contains(st)) {
                result.add(st);
            }
        }

        // Creating a key:StartTag map based on the previous results
        Map<String, StartTag> stMap = new TreeMap<>();
        for (StartTag st : result) {
            if (st.getAttributeValue("name") != null || st.getAttributeValue("id") != null) {
                String name =
                        (st.getAttributeValue("id") == null)
                                ? st.getAttributeValue("name")
                                : st.getAttributeValue("id");
                if (name != null) {
                    stMap.put(name, st);
                }
            }
        }
        return stMap;
    }

    // TODO: see how to manage exceptions in this class...
    private static String extractViewstate(Map<String, StartTag> lstHiddenFields) {
        // If the viewstate isn't split, we simply return the Viewstate object
        // based on the field
        if (!lstHiddenFields.containsKey("__VIEWSTATEFIELDCOUNT")) {
            return lstHiddenFields.get("__VIEWSTATE").getAttributeValue("value");
        } else {
            // ViewState was split
            isSplit = true;
        }

        // Otherwise we concatenate manually the viewstate
        StringBuilder tmpValue = new StringBuilder();

        tmpValue.append(lstHiddenFields.get("__VIEWSTATE").getAttributeValue("value"));

        int max =
                Integer.parseInt(
                        lstHiddenFields.get("__VIEWSTATEFIELDCOUNT").getAttributeValue("value"));
        numSplitFields = max;
        for (int i = 1; i < max; i++) {
            tmpValue.append(lstHiddenFields.get("__VIEWSTATE" + i).getAttributeValue("value"));
        }

        return tmpValue.toString();
    }

    public boolean isValid() {
        return this.isValid && (this.getVersion() != ViewstateVersion.UNKNOWN);
    }

    public boolean isSplit() {
        return isSplit;
    }

    public int getSplitFieldCount() {
        return numSplitFields;
    }

    // TODO: enhance this code, as it WILL fail at least in the following cases:
    // - MAC is set to another value than the default (e.g. bigger or smaller
    // than 20 characters)
    // - some ASP.NET 3.5 stuff, especially linked with SharePoint, don't seem
    // to use 'd' as null character
    // - some Viewstates don't have their last 2 objects set to null

    // TODO: replace this bool by a more fuzzy indicator
    public boolean hasMACtest1() {
        // Decode value first
        String dVal = new String(decode());

        int l = dVal.length();
        // By default, the MAC is 20 characters long
        String lastCharsBeforeMac = dVal.substring(l - 22, l - 20);

        if (this.version.equals(ViewstateVersion.ASPNET2)) return lastCharsBeforeMac.equals("dd");

        if (this.version.equals(ViewstateVersion.ASPNET1)) return lastCharsBeforeMac.equals(">>");

        return true;
    }

    public boolean hasMACtest2() {
        // Decode value first
        String dVal = new String(decode());

        int l = dVal.length();
        // By default, the MAC is 20 characters long
        String lastCharsBeforeMac = dVal.substring(l - 2);

        if (this.version.equals(ViewstateVersion.ASPNET2)) return !lastCharsBeforeMac.equals("dd");

        if (this.version.equals(ViewstateVersion.ASPNET1)) return !lastCharsBeforeMac.equals(">>");

        return true;
    }

    public String encode(byte[] plain) {
        this.value = Base64.getEncoder().encodeToString(plain);
        return this.value;
    }

    public byte[] decode() {
        return decode(this.value);
    }

    public byte[] decode(String base64) {
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            logger.error("Could not decode ASPViewState: " + e.getMessage(), e);
            return base64.getBytes();
        }
    }

    public boolean isLatestAspNetVersion() {
        return this.getVersion().isLatest();
    }

    public ViewstateVersion getVersion() {
        return this.version;
    }

    private void setVersion() {
        this.version = ViewstateVersion.UNKNOWN;

        if (this.value.startsWith("/w")) this.version = ViewstateVersion.ASPNET2;

        if (this.value.startsWith("dD")) this.version = ViewstateVersion.ASPNET1;
    }

    /* TODO once we have good Viewstate 1 & 2 parsers */
    public Object[] getObjectTree() throws Exception {
        throw new UnsupportedOperationException("Not implemented (yet)");
    }

    public Object[] getStateBagTree() throws Exception {
        throw new UnsupportedOperationException("Not implemented (yet)");
    }

    public Object[] getSerializedComponentsTree() throws Exception {
        throw new UnsupportedOperationException("Not implemented (yet)");
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
}
