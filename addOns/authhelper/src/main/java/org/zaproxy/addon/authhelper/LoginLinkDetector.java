/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import java.util.List;
import java.util.Locale;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class LoginLinkDetector {

    public static List<WebElement> getLoginLinks(WebDriver wd, List<String> loginLabels) {
        // Try finding links first
        List<WebElement> loginLinks = findElementsByTagAndLabels(wd, "a", loginLabels);
        if (!loginLinks.isEmpty()) {
            return loginLinks;
        }
        // If no links found, try buttons
        return findElementsByTagAndLabels(wd, "button", loginLabels);
    }

    private static List<WebElement> findElementsByTagAndLabels(
            WebDriver wd, String tag, List<String> labels) {
        return wd.findElements(By.tagName(tag)).stream()
                .filter(element -> elementContainsText(element, labels))
                .toList();
    }

    private static boolean elementContainsText(WebElement element, List<String> searchTexts) {
        String txt = element.getText().toLowerCase(Locale.ROOT);
        return searchTexts.stream().anyMatch(txt::contains);
    }

    public static List<Element> getLoginLinks(Source src, List<String> loginLabels) {
        // Try finding links first
        List<Element> loginLinks = findElementsByTagAndLabels(src, HTMLElementName.A, loginLabels);
        if (!loginLinks.isEmpty()) {
            return loginLinks;
        }
        // If no links found, try buttons
        return findElementsByTagAndLabels(src, HTMLElementName.BUTTON, loginLabels);
    }

    private static List<Element> findElementsByTagAndLabels(
            Source src, String tag, List<String> labels) {
        return src.getAllElements(tag).stream()
                .filter(element -> elementContainsText(element, labels))
                .toList();
    }

    private static boolean elementContainsText(Element element, List<String> searchTexts) {
        String txt = element.getTextExtractor().toString().toLowerCase(Locale.ROOT);
        return searchTexts.stream().anyMatch(txt::contains);
    }
}
