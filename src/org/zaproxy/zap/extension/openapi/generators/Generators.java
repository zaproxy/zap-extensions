/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
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
 */
package org.zaproxy.zap.extension.openapi.generators;

import java.util.ArrayList;
import java.util.List;

public class Generators {

    private ValueGenerator valueGenerator;
    private ArrayGenerator arrayGenerator;
    private ModelGenerator modelGenerator;
    private BodyGenerator bodyGenerator;
    private DataGenerator dataGenerator;
    private FormGenerator formGenerator;
    private PathGenerator pathGenerator;
    private List<String> errorMessages = new ArrayList<String>();


    public Generators(org.zaproxy.zap.model.ValueGenerator valueGenerator) {
        this.valueGenerator = new ValueGenerator(valueGenerator);
        this.modelGenerator = new ModelGenerator();
        this.dataGenerator = new DataGenerator(this);
        this.bodyGenerator = new BodyGenerator(this);
        this.arrayGenerator = new ArrayGenerator(this.dataGenerator);
        this.formGenerator = new FormGenerator(this.dataGenerator);
        this.pathGenerator = new PathGenerator(this.dataGenerator);
    }

    public ModelGenerator getModelGenerator() {
        return modelGenerator;
    }

    public ArrayGenerator getArrayGenerator() {
        return arrayGenerator;
    }

    public BodyGenerator getBodyGenerator() {
        return bodyGenerator;
    }

    public DataGenerator getDataGenerator() {
        return dataGenerator;
    }

    public FormGenerator getFormGenerator() {
        return formGenerator;
    }

    public PathGenerator getPathGenerator() {
        return pathGenerator;
    }
    
    public void addErrorMessage (String error) {
        this.errorMessages.add(error);
    }
    
    public List<String> getErrorMessages() {
        return this.errorMessages;
    }
    
    public ValueGenerator getValueGenerator() {
        return this.valueGenerator;
    }
}
