/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.tagcreator;

import java.awt.GridLayout;
import java.awt.Panel;
import java.text.MessageFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.AbstractHttpFuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.utils.ZapTextField;

public class HttpFuzzerMessageProcessorTagUIPanel
        extends AbstractHttpFuzzerMessageProcessorUIPanel<
                HttpFuzzerMessageProcessorTagCreator, HttpFuzzerMessageProcessorTagUI> {

    private static final String MATCH_BY_REGEX_LABEL_REGEX =
            Constant.messages.getString("fuzz.httpfuzzer.processor.tagcreator.matchbyregex.regex");
    private static final String MATCH_BY_REGEX_LABEL_TAG =
            Constant.messages.getString("fuzz.httpfuzzer.processor.tagcreator.matchbyregex.tag");
    private static final String MATCH_BY_REGEX_NAME =
            Constant.messages.getString("fuzz.httpfuzzer.processor.tagcreator.matchbyregex.name");
    private static final String EXTRACT_BY_REGEX_LABEL_REGEX =
            Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.tagcreator.extractbyregex.regex");
    private static final String EXTRACT_BY_REGEX_NAME =
            Constant.messages.getString("fuzz.httpfuzzer.processor.tagcreator.extractbyregex.name");
    private static final String VALIDATION_MESSAGEBOX_TITLE =
            Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.tagcreator.validation.messageboxtitle");
    private static final String VALIDATION_TEXTFIELDS_ARE_REQUIRED =
            Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.tagcreator.validation.textfieldsarerequired");
    private static final String VALIDATION_REGEX_SYNTAX_ERROR =
            Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.tagcreator.validation.regexsyntaxerror");
    private static final String VALIDATION_REGEX_AT_LEAST_ONE_GROUP =
            Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.tagcreator.validation.regexatleastonegroup");
    private static final boolean INVALID = false;
    private static final boolean VALID = true;
    private final JPanel fieldsPanel;
    private ButtonGroup radioGroup;

    private ZapTextField matchByRegexFieldRegex;
    private ZapTextField matchByRegexFieldTag;
    private JRadioButton matchByRegexRadio;

    private ZapTextField extractByRegexFieldRegex;
    private JRadioButton extractByRegexRadio;

    public HttpFuzzerMessageProcessorTagUIPanel() {
        fieldsPanel = new JPanel();
        radioGroup = new ButtonGroup();
        GridLayout layout = new GridLayout(5, 2);
        fieldsPanel.setLayout(layout);
        createMatchByRegexControl();
        createExtractByRegexControl();
    }

    private void createExtractByRegexControl() {
        extractByRegexRadio = new JRadioButton();
        addRadioButton(extractByRegexRadio, EXTRACT_BY_REGEX_NAME, false);

        extractByRegexFieldRegex = new ZapTextField();
        addLabelWithTextField(extractByRegexFieldRegex, EXTRACT_BY_REGEX_LABEL_REGEX);
    }

    private void createMatchByRegexControl() {
        matchByRegexRadio = new JRadioButton();
        addRadioButton(matchByRegexRadio, MATCH_BY_REGEX_NAME, true);

        matchByRegexFieldRegex = new ZapTextField();
        addLabelWithTextField(matchByRegexFieldRegex, MATCH_BY_REGEX_LABEL_REGEX);

        matchByRegexFieldTag = new ZapTextField();
        addLabelWithTextField(matchByRegexFieldTag, MATCH_BY_REGEX_LABEL_TAG);
    }

    private void addRadioButton(JRadioButton radio, String name, boolean selected) {
        radio.setText(name);
        radio.setSelected(selected);
        fieldsPanel.add(radio);
        fieldsPanel.add(new Panel());
        radioGroup.add(radio);
    }

    private void addLabelWithTextField(JTextField textField, String labelName) {
        JLabel label = new JLabel(labelName, JLabel.TRAILING);
        fieldsPanel.add(label);
        label.setLabelFor(textField);
        fieldsPanel.add(textField);
    }

    @Override
    public JPanel getComponent() {
        return fieldsPanel;
    }

    @Override
    public void setFuzzerMessageProcessorUI(HttpFuzzerMessageProcessorTagUI processorUI) {
        TagRule rule = processorUI.getTagRule();
        if (rule.getClass() == MatchByRegexTagRule.class) {
            MatchByRegexTagRule tagRule = (MatchByRegexTagRule) rule;
            matchByRegexRadio.setSelected(true);
            setTextAndDiscardAllEdits(matchByRegexFieldRegex, tagRule.getRegex());
            setTextAndDiscardAllEdits(matchByRegexFieldTag, tagRule.getTag());
        } else if (rule.getClass() == ExtractByRegexTagRule.class) {
            ExtractByRegexTagRule tagRule = (ExtractByRegexTagRule) rule;
            extractByRegexRadio.setSelected(true);
            setTextAndDiscardAllEdits(extractByRegexFieldRegex, tagRule.getRegex());
        }
    }

    private void setTextAndDiscardAllEdits(ZapTextField zapTextField, String text) {
        zapTextField.setText(text);
        zapTextField.discardAllEdits();
    }

    @Override
    public HttpFuzzerMessageProcessorTagUI getFuzzerMessageProcessorUI() {
        TagRule tagRule = null;
        if (matchByRegexRadio.isSelected()) {
            tagRule =
                    new MatchByRegexTagRule(
                            matchByRegexFieldRegex.getText(), matchByRegexFieldTag.getText());

        } else if (extractByRegexRadio.isSelected()) {
            tagRule = new ExtractByRegexTagRule(extractByRegexFieldRegex.getText());
        }
        return new HttpFuzzerMessageProcessorTagUI(tagRule);
    }

    @Override
    public void clear() {
        matchByRegexRadio.setSelected(true);
        setTextAndDiscardAllEdits(matchByRegexFieldRegex, "");
        setTextAndDiscardAllEdits(matchByRegexFieldTag, "");
        setTextAndDiscardAllEdits(extractByRegexFieldRegex, "");
    }

    @Override
    public boolean validate() {
        if (matchByRegexRadio.isSelected()) {
            return validateMatchByRegex();
        } else if (extractByRegexRadio.isSelected()) {
            return validateExtractByRegex();
        }
        return INVALID;
    }

    private boolean validateMatchByRegex() {
        return isTextFieldNotEmpty(matchByRegexFieldTag)
                && isTextFieldNotEmpty(matchByRegexFieldRegex)
                && hasTextFieldValidRegex(matchByRegexFieldRegex);
    }

    private boolean hasTextFieldValidRegex(ZapTextField zapTextField) {
        String regex = zapTextField.getText();
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException exception) {
            String errorMessage =
                    MessageFormat.format(VALIDATION_REGEX_SYNTAX_ERROR, exception.getDescription());
            return showError(errorMessage);
        }
        return VALID;
    }

    private boolean isTextFieldNotEmpty(ZapTextField zapTextField) {
        if (zapTextField.getText().length() == 0) {
            return showError(VALIDATION_TEXTFIELDS_ARE_REQUIRED);
        }
        return VALID;
    }

    private boolean showError(String text) {
        JOptionPane.showMessageDialog(
                null, text, VALIDATION_MESSAGEBOX_TITLE, JOptionPane.INFORMATION_MESSAGE);
        return INVALID;
    }

    private boolean validateExtractByRegex() {
        return isTextFieldNotEmpty(extractByRegexFieldRegex)
                && hasTextFieldValidRegex(extractByRegexFieldRegex)
                && hasTextFieldRegexAtLeastOneGroup(extractByRegexFieldRegex);
    }

    private boolean hasTextFieldRegexAtLeastOneGroup(ZapTextField zapTextField) {
        String regex = zapTextField.getText();
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher("");
        if (matcher.groupCount() == 0) {
            return showError(VALIDATION_REGEX_AT_LEAST_ONE_GROUP);
        }
        return VALID;
    }
}
