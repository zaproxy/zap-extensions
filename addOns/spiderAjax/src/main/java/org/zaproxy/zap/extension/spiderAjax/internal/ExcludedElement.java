/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax.internal;

import java.util.List;
import java.util.Objects;
import org.zaproxy.zap.utils.EnableableInterface;

/** A (clickable) element excluded from crawling. */
public class ExcludedElement implements EnableableInterface {

    /**
     * The result of validating a new {@link ExcludedElement}.
     *
     * @see ExcludedElement#validate(ExcludedElement, ExcludedElement, List)
     */
    public enum ValidationResult {
        /** The {@code description} is empty. */
        EMPTY_DESCRIPTION,
        /** The {@code element} is empty. */
        EMPTY_ELEMENT,
        /** The {@code description} duplicates an existing element. */
        DUPLICATED,
        /**
         * One of the other data is missing (e.g. {@code xpath}, {@code text}, {@code attributeName}
         * or {@code attributeValue}}.
         */
        MISSING_DATA,
        /** Both {@code attributeName} and {@code attributeValue} value must be non-empty. */
        MISSING_ATTRIBUTE_FIELD,
        /** The {@code ExcludedElement} is valid. */
        VALID,
    }

    private String description;
    private String element;
    private String xpath;
    private String text;
    private String attributeName;
    private String attributeValue;
    private boolean enabled;

    public ExcludedElement() {}

    public ExcludedElement(ExcludedElement other) {
        description = other.description;
        element = other.element;
        xpath = other.xpath;
        text = other.text;
        attributeName = other.attributeName;
        attributeValue = other.attributeValue;
        enabled = other.enabled;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getElement() {
        return element;
    }

    public void setElement(String element) {
        this.element = element;
    }

    public String getXpath() {
        return xpath;
    }

    public void setXpath(String xpath) {
        this.xpath = xpath;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    public String getAttributeValue() {
        return attributeValue;
    }

    public void setAttributeValue(String attributeValue) {
        this.attributeValue = attributeValue;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                attributeName, attributeValue, enabled, description, element, text, xpath);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExcludedElement)) {
            return false;
        }
        ExcludedElement other = (ExcludedElement) obj;
        return Objects.equals(attributeName, other.attributeName)
                && Objects.equals(attributeValue, other.attributeValue)
                && enabled == other.enabled
                && Objects.equals(description, other.description)
                && Objects.equals(element, other.element)
                && Objects.equals(text, other.text)
                && Objects.equals(xpath, other.xpath);
    }

    /**
     * Validates the {@code newElement}.
     *
     * @param oldElement the element prior the changes, if any.
     * @param newElement the new element.
     * @param elements the existing elements.
     * @return the result of the validation.
     */
    public static ValidationResult validate(
            ExcludedElement oldElement,
            ExcludedElement newElement,
            List<? extends ExcludedElement> elements) {
        if (isEmpty(newElement.getDescription())) {
            return ValidationResult.EMPTY_DESCRIPTION;
        }

        if (isEmpty(newElement.getElement())) {
            return ValidationResult.EMPTY_ELEMENT;
        }

        boolean attributeNameEmpty = isEmpty(newElement.getAttributeName());
        boolean attributeValueEmpty = isEmpty(newElement.getAttributeValue());
        if (isEmpty(newElement.getXpath())
                && isEmpty(newElement.getText())
                && attributeNameEmpty
                && attributeValueEmpty) {
            return ValidationResult.MISSING_DATA;
        } else if ((!attributeNameEmpty && attributeValueEmpty)
                || (attributeNameEmpty && !attributeValueEmpty)) {
            return ValidationResult.MISSING_ATTRIBUTE_FIELD;
        }

        if (oldElement == null
                || !Objects.equals(oldElement.getDescription(), newElement.getDescription())) {
            String description = newElement.getDescription();
            for (ExcludedElement e : elements) {
                if (description.equals(e.getDescription())) {
                    return ValidationResult.DUPLICATED;
                }
            }
        }

        return ValidationResult.VALID;
    }

    private static boolean isEmpty(String string) {
        return string == null || string.isBlank();
    }
}
