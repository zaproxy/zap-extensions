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
package org.zaproxy.addon.reports.sarif;

import org.zaproxy.addon.reports.sarif.SarifResult.SarifBody;

public class SarifBodyStartLineFinder {

    public static final SarifBodyStartLineFinder DEFAULT = new SarifBodyStartLineFinder();

    /**
     * SARIF supports a region information with a start line. (see
     * https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317682 ) This
     * class does find the start line for text body content of given parameter
     *
     * @param body the body to inspect
     * @param toSearch search string which will identify the line
     * @return 0 - when toSearch is not found inside text body, otherwise line number
     */
    public long findStartLine(SarifBody body, String toSearch) {
        if (body == null) {
            return 0;
        }
        String text = body.getText();
        if (text == null) {
            return 0;
        }

        String[] lines = text.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String content = lines[i];
            int indexOf = content.indexOf(toSearch);
            if (indexOf != -1) {
                return i + 1;
            }
        }
        return 0;
    }
}
