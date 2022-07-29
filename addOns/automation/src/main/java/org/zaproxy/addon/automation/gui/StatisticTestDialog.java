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
package org.zaproxy.addon.automation.gui;

import java.util.Arrays;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest.OnFail;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest.Operator;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class StatisticTestDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.statistictest.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String STATISTIC_PARAM = "automation.dialog.statistictest.statistic";
    private static final String SITE_PARAM = "automation.dialog.statistictest.site";
    private static final String OPERATOR_PARAM = "automation.dialog.statistictest.operator";
    private static final String VALUE_PARAM = "automation.dialog.statistictest.value";
    private static final String ON_FAIL_PARAM = "automation.dialog.statistictest.onfail";

    private AutomationStatisticTest test;

    public StatisticTestDialog(AutomationStatisticTest test) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 250));
        this.test = test;

        this.addTextField(NAME_PARAM, test.getData().getName());
        this.addComboField(
                ON_FAIL_PARAM,
                Arrays.asList(OnFail.values()).stream()
                        .map(OnFail::toString)
                        .toArray(String[]::new),
                test.getData().getOnFail().toString());
        int i = 0;
        Long l = test.getData().getValue();
        if (l != null) {
            try {
                i = Math.toIntExact(test.getData().getValue());
            } catch (Exception e) {
                i = Integer.MAX_VALUE;
            }
        }
        this.addTextField(STATISTIC_PARAM, test.getData().getStatistic());
        this.addTextField(SITE_PARAM, test.getData().getSite());

        this.addComboField(
                OPERATOR_PARAM,
                Arrays.asList(Operator.values()).stream()
                        .map(Operator::getSymbol)
                        .toArray(String[]::new),
                test.getData().getOperator());

        this.addNumberField(VALUE_PARAM, 0, Integer.MAX_VALUE, i);
        this.addPadding();
    }

    @Override
    public void save() {
        this.test.getData().setName(this.getStringValue(NAME_PARAM));
        this.test.getData().setStatistic(this.getStringValue(STATISTIC_PARAM));
        this.test.getData().setSite(this.getStringValue(SITE_PARAM));
        this.test.getData().setOperator(this.getStringValue(OPERATOR_PARAM));
        this.test.getData().setValue(Long.valueOf(this.getIntValue(VALUE_PARAM)));
        this.test.getData().setOnFail(OnFail.i18nToOnFail(this.getStringValue(ON_FAIL_PARAM)));
        this.test.getJob().getPlan().setChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
