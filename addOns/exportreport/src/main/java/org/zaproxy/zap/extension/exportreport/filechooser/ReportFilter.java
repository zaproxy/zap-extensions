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
package org.zaproxy.zap.extension.exportreport.filechooser;

import java.io.File;
import javax.swing.filechooser.FileFilter;
import org.parosproxy.paros.Constant;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

public class ReportFilter extends FileFilter {

    // Accept all directories and all specified files.
    private FileList list;
    private String search;

    public ReportFilter(FileList list, String search) {
        this.list = list;
        this.search = search;
    }

    // what files and folders are visible
    @Override
    public boolean accept(File f) {
        if (f.isDirectory()) {
            return true;
        }
        if (f.isFile()) {
            String ext = Utils.getExtension(f);
            if (ext != null) {
                if (!Utils.ALL.equals(search)) {
                    if (ext.equalsIgnoreCase(list.getExtension(search))) {
                        return true;
                    }
                } else {
                    boolean bool = false;
                    for (int i = 0; i < list.size(); i++) {

                        if (ext.equals(list.getExtension(i))) {
                            bool = true;
                        }
                    }
                    return bool;
                }
            }
        }
        return false;
    }

    // The description of this filter drop down list items
    @Override
    public String getDescription() {
        String strExtension = "";
        if (!Utils.ALL.equals(search)) {
            strExtension = String.format(" (*%s)", list.getExtension(search));
        } else {
            strExtension = Constant.messages.getString("exportreport.message.notice.all") + " (";
            for (int i = 0; i < list.size(); i++) {
                strExtension = strExtension + String.format("*.%s", list.getExtension(i) + ", ");
            }
            strExtension = strExtension.substring(0, strExtension.length() - 2) + ")";
        }
        return list.getDescription(search) + strExtension;
    }

    public String getExtensionByDescription(String description) {
        return list.getExtensionByDescription(description);
    }
}
