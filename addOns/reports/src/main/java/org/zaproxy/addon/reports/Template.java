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
package org.zaproxy.addon.reports;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import org.thymeleaf.templatemode.TemplateMode;
import org.yaml.snakeyaml.Yaml;

public class Template {

    private String displayName;
    private String configName;
    private File reportTemplateFile;
    private String extension;
    private String format;
    private TemplateMode mode;

    public Template(File templateYaml) throws IOException {
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data;
        try (FileInputStream in = new FileInputStream(templateYaml)) {
            data = yaml.load(in);
        }
        configName = templateYaml.getParentFile().getName();
        setDisplayName(this.getString("name", data, false));
        setFormat(this.getString("format", data, false));
        setExtension(this.getString("extension", data, false));
        if ("pdf".equalsIgnoreCase(extension)) {
            // Special case, PDF report templates are really HTML
            reportTemplateFile = new File(templateYaml.getParent(), "report.html");
        } else {
            reportTemplateFile = new File(templateYaml.getParent(), "report." + extension);
        }
        if (!reportTemplateFile.exists() || !reportTemplateFile.canRead()) {
            throw new IllegalArgumentException(
                    "Cannot read " + reportTemplateFile.getAbsolutePath());
        }
        setMode(TemplateMode.parse(this.getString("mode", data, false)));
    }

    private String getString(String key, LinkedHashMap<?, ?> data, boolean optional)
            throws IllegalArgumentException {
        if (data.containsKey(key)) {
            Object o = data.get(key);
            if (o instanceof String) {
                return (String) o;
            }
        }
        if (!optional) {
            throw new IllegalArgumentException("Template missing key: " + key);
        }
        return null;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getConfigName() {
        return configName;
    }

    public File getReportTemplateFile() {
        return reportTemplateFile;
    }

    public void setReportTemplateFile(File reportTemplateFile) {
        this.reportTemplateFile = reportTemplateFile;
    }

    public String getExtension() {
        return extension;
    }

    public void setExtension(String extension) {
        this.extension = extension;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public TemplateMode getMode() {
        return mode;
    }

    public void setMode(TemplateMode mode) {
        this.mode = mode;
    }

    public File getResourcesDir() {
        if (reportTemplateFile == null) {
            return null;
        }
        return new File(this.reportTemplateFile.getParentFile(), "resources");
    }
}
