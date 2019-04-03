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

import java.util.AbstractList;
import java.util.ArrayList;

import javax.swing.ImageIcon;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

public class FileList extends AbstractList<FileType> {
    private ArrayList<FileType> fileList;

    public FileList() {
        fileList = new ArrayList<FileType>();
    }

    public void add(String search, String type, String extension, String description, String htmlicon, boolean enabled) {

        FileType data = new FileType(fileList.size(), search, type, extension, description, htmlicon, enabled);
        if (!fileList.contains(data)) {
            fileList.add(data);
        }
    }

    @Override
    public FileType get(int index) {
        return fileList.get(index);
    }

    public int getIndex(String search) {
        for (FileType obj : fileList) {
            if (obj.getSearch().equalsIgnoreCase(search))
                return obj.getIndex();
        }
        return -1;
    }

    public String getSearch(int index) {
        return fileList.get(index).getSearch();
    }

    public String getType(String search) {
        for (FileType obj : fileList) {
            if ((obj.getSearch()).equalsIgnoreCase(search))
                return obj.getType();
        }
        return "";
    }

    public String getExtension(int index) {
        for (FileType obj : fileList) {
            if (obj.getIndex() == index)
                return obj.getExtension();
        }
        return "";
    }

    public String compareExtension(String str) {
        for (int i = 0; i < fileList.size(); i++) {
            String tmpExt = getExtension(i);
            if (str.endsWith("." + tmpExt)) {
                int length = (str.lastIndexOf(tmpExt) - 1);
                if (length > 0) {
                    return tmpExt;
                }
            }
        }
        return "";
    }

    public String getExtensionByDescription(String description) {
        String temp = "";
        for (FileType obj : fileList) {
            if (description.contains(obj.getDescription())) {
                temp = obj.getExtension();
                break;
            }
        }
        return temp;
    }

    public String getExtension(String search) {
        for (FileType obj : fileList) {
            if ((obj.getSearch()).equalsIgnoreCase(search))
                return obj.getExtension();
        }
        return "";
    }

    public String getDescription(String search) {
        for (FileType obj : fileList) {
            if ((obj.getSearch()).equalsIgnoreCase(search))
                return obj.getDescription();
        }
        return "";
    }

    public ImageIcon getIcon(String search) {
        for (FileType obj : fileList) {
            if ((obj.getSearch()).equalsIgnoreCase(search))
                return obj.getIcon();
        }
        return null;
    }

    @Override
    public int size() {
        return fileList.size();
    }
}