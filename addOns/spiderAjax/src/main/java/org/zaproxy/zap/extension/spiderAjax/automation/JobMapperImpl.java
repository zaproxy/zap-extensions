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
package org.zaproxy.zap.extension.spiderAjax.automation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.processing.Generated;
import org.zaproxy.zap.extension.spiderAjax.internal.ExcludedElement;

@Generated(value = "org.mapstruct.ap.MappingProcessor")
class JobMapperImpl implements JobMapper {

    @Override
    public ExcludedElement toModel(ExcludedElementAuto source) {
        if (source == null) {
            return null;
        }

        ExcludedElement excludedElement = new ExcludedElement();

        excludedElement.setDescription(toString(source.getDescription()));
        excludedElement.setElement(toString(source.getElement()));
        excludedElement.setXpath(toString(source.getXpath()));
        excludedElement.setText(toString(source.getText()));
        excludedElement.setAttributeName(toString(source.getAttributeName()));
        excludedElement.setAttributeValue(toString(source.getAttributeValue()));
        excludedElement.setEnabled(source.isEnabled());

        return excludedElement;
    }

    @Override
    public List<ExcludedElement> toModel(List<ExcludedElementAuto> source) {
        if (source == null) {
            return null;
        }

        List<ExcludedElement> list = new ArrayList<>(source.size());
        for (ExcludedElementAuto excludedElementAuto : source) {
            list.add(toModel(excludedElementAuto));
        }

        return list;
    }

    @Override
    public ExcludedElementAuto toDto(ExcludedElement source) {
        if (source == null) {
            return null;
        }

        ExcludedElementAuto excludedElementAuto = new ExcludedElementAuto();

        excludedElementAuto.setDescription(toString(source.getDescription()));
        excludedElementAuto.setElement(toString(source.getElement()));
        excludedElementAuto.setXpath(toString(source.getXpath()));
        excludedElementAuto.setText(toString(source.getText()));
        excludedElementAuto.setAttributeName(toString(source.getAttributeName()));
        excludedElementAuto.setAttributeValue(toString(source.getAttributeValue()));
        excludedElementAuto.setEnabled(source.isEnabled());

        return excludedElementAuto;
    }

    @Override
    public List<ExcludedElementAuto> toDto(List<ExcludedElement> source) {
        if (source == null) {
            return null;
        }

        List<ExcludedElementAuto> list = new ArrayList<>(source.size());
        for (ExcludedElement excludedElement : source) {
            list.add(toDto(excludedElement));
        }

        return list;
    }

    @Override
    public ExcludedElementAuto toDto(Map<String, ?> data) {
        if (data == null) {
            return null;
        }

        ExcludedElementAuto excludedElementAuto = new ExcludedElementAuto();

        if (data.containsKey("description")) {
            excludedElementAuto.setDescription(toString(data.get("description")));
        }
        if (data.containsKey("element")) {
            excludedElementAuto.setElement(toString(data.get("element")));
        }
        if (data.containsKey("xpath")) {
            excludedElementAuto.setXpath(toString(data.get("xpath")));
        }
        if (data.containsKey("text")) {
            excludedElementAuto.setText(toString(data.get("text")));
        }
        if (data.containsKey("attributeName")) {
            excludedElementAuto.setAttributeName(toString(data.get("attributeName")));
        }
        if (data.containsKey("attributeValue")) {
            excludedElementAuto.setAttributeValue(toString(data.get("attributeValue")));
        }

        return excludedElementAuto;
    }

    @Override
    public List<ExcludedElementAuto> toDtoFromPlan(List<Map<String, ?>> data) {
        if (data == null) {
            return null;
        }

        List<ExcludedElementAuto> list = new ArrayList<>(data.size());
        for (Map<String, ?> map : data) {
            list.add(toDto(map));
        }

        return list;
    }
}
