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
package org.zaproxy.addon.exim;

import java.io.File;
import javax.swing.filechooser.FileFilter;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

public class EximFileChooser extends WritableFileChooser {

    private static final long serialVersionUID = 495386048962640141L;
    private final String fileExtension;

    public EximFileChooser(String fileExtension, String fileDescription) {
        super(Model.getSingleton().getOptionsParam().getUserDirectory());
        this.fileExtension = fileExtension;
        setFileFilter(new EximFileFilter(fileExtension, fileDescription));
    }

    @Override
    public void approveSelection() {
        File file = getSelectedFile();
        if (file != null) {
            String fileName = file.getAbsolutePath();
            if (!fileName.endsWith(fileExtension)) {
                fileName += fileExtension;
                setSelectedFile(new File(fileName));
            }
        }

        super.approveSelection();
    }

    private static class EximFileFilter extends FileFilter {

        private final String fileExtension;
        private final String fileDescription;

        EximFileFilter(String fileExtension, String fileDescription) {
            this.fileExtension = fileExtension;
            this.fileDescription = fileDescription;
        }

        @Override
        public boolean accept(File file) {
            return file.isDirectory() || (file.isFile() && file.getName().endsWith(fileExtension));
        }

        @Override
        public String getDescription() {
            return fileDescription;
        }
    }
}
