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
import java.net.URL;
import java.net.URLClassLoader;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ResourceBundle;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.thymeleaf.templatemode.TemplateMode;
import org.yaml.snakeyaml.Yaml;

public class Template {

    private static final Logger LOGGER = LogManager.getLogger(Template.class);

    private String displayName;
    private String configName;
    private File reportTemplateFile;
    private String extension;
    private String format;
    private TemplateMode mode;
    private List<String> sections = new ArrayList<>();
    private List<String> themes = new ArrayList<>();
    private ResourceBundle msgs = null;
    private Boolean hasMsgs = null;
    private URLClassLoader classloader = null;

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
        if (data.containsKey("sections")) {
            Object o = data.get("sections");
            if (o instanceof ArrayList) {
                ArrayList<?> list = (ArrayList<?>) o;
                for (Object l : list) {
                    if (isValidComponentName(l)) {
                        sections.add(l.toString());
                    } else {
                        LOGGER.error(
                                "Template '{}' has invalid section: '{}' - must be alphanumeric and not start with a number",
                                configName,
                                l);
                    }
                }
            }
        }
        if (data.containsKey("themes")) {
            Object o = data.get("themes");
            if (o instanceof ArrayList) {
                ArrayList<?> list = (ArrayList<?>) o;
                for (Object l : list) {
                    if (isValidComponentName(l)) {
                        themes.add(l.toString());
                    } else {
                        LOGGER.error(
                                "Template '{}' has invalid theme: '{}' - must be alphanumeric and not start with a number",
                                configName,
                                l);
                    }
                }
            }
        }
    }

    private static boolean isValidComponentName(Object o) {
        if (o == null) {
            return false;
        }
        String str = o.toString();
        if (str.isEmpty()) {
            return false;
        }
        if (Character.isDigit(str.charAt(0))) {
            return false;
        }
        if (!StringUtils.isAlphanumeric(str)) {
            return false;
        }
        return true;
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

    public List<String> getSections() {
        return Collections.unmodifiableList(sections);
    }

    public List<String> getThemes() {
        return Collections.unmodifiableList(themes);
    }

    public List<String> getThemeNames() {
        List<String> themeNames = new ArrayList<>(themes.size());
        for (String theme : themes) {
            themeNames.add(getThemeName(theme));
        }
        return themeNames;
    }

    public String getThemeForName(String name) {
        if (name == null) {
            return null;
        }
        for (String theme : themes) {
            if (name.equals(getThemeName(theme))) {
                return theme;
            }
        }
        return null;
    }

    public String getThemeName(String theme) {
        if (theme == null) {
            return null;
        }
        return getI18nString("report.template.theme." + theme, null);
    }

    /**
     * Returns the i18n translation for the given key if present in a local properties file. Will
     * return null otherwise.
     *
     * @param key the i18n key
     * @param messageParameters any parameters for the associated translation
     * @return the i18n translation for the given key if present in a local properties file. Will
     *     return null otherwise.
     */
    public String getI18nString(String key, Object[] messageParameters) {
        if (hasMsgs == null) {
            try {
                File dir = this.reportTemplateFile.getParentFile();
                URL[] urls = {dir.toURI().toURL()};
                classloader = new URLClassLoader(urls);
                msgs = ResourceBundle.getBundle("Messages", Constant.getLocale(), classloader);
                hasMsgs = Boolean.TRUE;
            } catch (Exception e) {
                hasMsgs = Boolean.FALSE;
                return null;
            }
        }
        if (hasMsgs && msgs.containsKey(key)) {
            String str = msgs.getString(key);
            if (messageParameters != null && messageParameters.length > 0) {
                return MessageFormat.format(str, messageParameters);
            }
            return str;
        }
        return null;
    }

    void unload() {
        if (classloader != null) {
            ResourceBundle.clearCache(classloader);
            try {
                classloader.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
}
