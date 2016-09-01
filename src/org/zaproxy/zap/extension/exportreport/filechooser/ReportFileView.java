/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * This file is based on the Paros code file ReportLastScan.java
 */
package org.zaproxy.zap.extension.exportreport.filechooser;

import java.io.File;

import javax.swing.Icon;
import javax.swing.filechooser.FileView;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

public class ReportFileView extends FileView {
    FileList list;

    public ReportFileView(FileList list) {
        this.list = list;
    }

    @Override
    public String getName(File f) {
        return null;
    }

    @Override
    public String getDescription(File f) {
        return null;
    }

    @Override
    public Boolean isTraversable(File f) {
        return null;
    }

    @Override
    public String getTypeDescription(File f) {
        String extension = Utils.getExtension(f);
        String type = null;
        if (extension != null) {
            for (int i = 0; i < list.size(); i++) {
                if (extension.equals(list.getExtension(i))) {
                    type = list.getType(list.getSearch(i));
                }
            }
        }
        return type;
    }

    @Override
    public Icon getIcon(File f) {
        String extension = Utils.getExtension(f);
        Icon icon = null;

        if (extension != null) {
            for (int i = 0; i < list.size(); i++) {
                if (extension.equals(list.getExtension(i))) {
                    icon = list.getIcon(list.getSearch(i));
                }
            }
        }
        return icon;
    }
}
