/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.ImageIcon;

public class Application {

    private String name;
    private String description;
    private String website;
    private ImageIcon icon = null;
    private List<String> categories = new ArrayList<>();
    private String cpe;
    private List<Map<String, AppPattern>> headers;
    private List<Map<String, AppPattern>> cookies;
    private List<AppPattern> url = new ArrayList<>();
    private List<AppPattern> html = new ArrayList<>();
    private List<Map<String, AppPattern>> metas;
    private List<Map<String, Map<String, Map<String, AppPattern>>>> dom;
    private List<String> simpleDom;
    private List<AppPattern> css = new ArrayList<>();
    private List<AppPattern> script = new ArrayList<>();

    private List<String> implies = new ArrayList<>();

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getWebsite() {
        return website;
    }

    public void setWebsite(String website) {
        this.website = website;
    }

    public List<String> getCategories() {
        return categories;
    }

    public void setCategories(List<String> categories) {
        this.categories = categories;
    }

    public String getCpe() {
        return cpe;
    }

    public void setCpe(String cpe) {
        this.cpe = cpe;
    }

    public void setHeaders(List<Map<String, AppPattern>> headers) {
        this.headers = headers;
    }

    public void setCookies(List<Map<String, AppPattern>> cookies) {
        this.cookies = cookies;
    }

    public void setUrl(List<AppPattern> url) {
        this.url = url;
    }

    public void setHtml(List<AppPattern> html) {
        this.html = html;
    }

    public void setCss(List<AppPattern> css) {
        this.css = css;
    }

    public void setMetas(List<Map<String, AppPattern>> metas) {
        this.metas = metas;
    }

    public void setDom(List<Map<String, Map<String, Map<String, AppPattern>>>> dom) {
        this.dom = dom;
    }

    void setSimpleDom(List<String> simpleDom) {
        this.simpleDom = simpleDom;
    }

    List<String> getSimpleDom() {
        return simpleDom;
    }

    public void setScript(List<AppPattern> script) {
        this.script = script;
    }

    public void setImplies(List<String> implies) {
        this.implies = implies;
    }

    public void addCategories(String category) {
        this.categories.add(category);
    }

    public List<Map<String, AppPattern>> getHeaders() {
        return headers;
    }

    public List<Map<String, AppPattern>> getCookies() {
        return cookies;
    }

    public void addHeaders(Map<String, AppPattern> header) {
        this.headers.add(header);
    }

    public List<AppPattern> getUrl() {
        return url;
    }

    public void addUrl(AppPattern u) {
        this.url.add(u);
    }

    public List<AppPattern> getHtml() {
        return html;
    }

    public void addHtml(AppPattern h) {
        this.html.add(h);
    }

    public List<Map<String, AppPattern>> getMetas() {
        return metas;
    }

    public void addMetas(Map<String, AppPattern> meta) {
        this.metas.add(meta);
    }

    public List<Map<String, Map<String, Map<String, AppPattern>>>> getDom() {
        return dom;
    }

    public List<AppPattern> getCss() {
        return css;
    }

    public void addMCss(AppPattern css) {
        this.css.add(css);
    }

    public List<AppPattern> getScript() {
        return script;
    }

    public void addScript(AppPattern s) {
        this.script.add(s);
    }

    public List<String> getImplies() {
        return implies;
    }

    public void addImplies(String i) {
        this.implies.add(i);
    }

    public ImageIcon getIcon() {
        return icon;
    }

    public void setIcon(ImageIcon icon) {
        this.icon = icon;
    }

    @Override
    public String toString() {
        return getName();
    }
}
