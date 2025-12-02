# [(${reportTitle})]

ZAP by [Checkmarx](https://checkmarx.com/).

[#th:block th:if="${reportData.isIncludeSection('alertcount')}"]
## [(#{report.alerts.summary})]

| [(#{report.alerts.summary.risklevel})] | [(#{report.alerts.summary.numalerts})] |
| --- | --- |
[#th:block th:each="i : ${#numbers.sequence(3, 0, -1)}"]| [(${helper.getRiskString(i)})] | [(${alertCounts.get(i)} ?: '0')] |
[/th:block]
[/th:block]

[#th:block th:if="${reportData.isIncludeSection('insights') && reportData.reportObjects.get('insightsList') != null}"]
## [(#{report.insights.title})]

| [(#{report.insights.level})] | [(#{report.insights.reason})] | [(#{report.insights.site})] | [(#{report.insights.desc})] | [(#{report.insights.stat})] |
| --- | --- | --- | --- | --- |
[#th:block th:each="ins : ${reportData.reportObjects.get('insightsList')}"]| [(${ins.level})] | [(${ins.reason})] | [(${ins.site})] | [(${ins.description})] | [(${ins.statisticStr})] |
[/th:block]
[/th:block]

[#th:block th:if="${reportData.isIncludeSection('instancecount')}"]
## [(#{report.alerts.list})]

| [(#{report.alerts.list.name})] | [(#{report.alerts.list.risklevel})] | [(#{report.alerts.list.numinstances})] |
| --- | --- | --- |
[#th:block th:each="alert: ${alertTree.children}"]| [(${alert.nodeName})] | [(${helper.getRiskString(alert.risk)})] | [#th:block th:if="${helper.isSystemic(alert)}"][(#{report.alerts.list.systemic})][/th:block][#th:block th:unless="${helper.isSystemic(alert)}"][(${alert.childCount})][/th:block] |
[/th:block]
[/th:block]

[#th:block th:if="${reportData.isIncludeSection('alertdetails')}"]
## [(#{report.alerts.detail})]

[#th:block th:each="alert: ${alertTree.children}"]
[#th:block th:if="${alert.userObject.pluginId >= 0}"]
### [ [(${alert.nodeName})] ](https://www.zaproxy.org/docs/alerts/[(${alert.userObject.pluginId})]/)
[/th:block]
[#th:block th:if="${alert.userObject.pluginId < 0}"]
### [(${alert.nodeName})]
[/th:block]

##### [(${helper.getRiskString(alert.risk) + ' (' + helper.getConfidenceString(alert.userObject.confidence) + ')'})]

### [(#{report.alerts.detail.description})]

[(${alert.userObject.description})]
[#th:block th:each="instance: ${alert.children}"]
* [(#{report.alerts.detail.url})]: [(${#strings.replace(#uris.escapePath(instance.userObject.uri), ')', '&29')})]
[#th:block th:if="${helper.getNodeName(instance.userObject) != null}"]  * [(#{report.alerts.detail.nodename})]: `[(${helper.getNodeName(instance.userObject)})]`[/th:block]
  * [(#{report.alerts.detail.method})]: `[(${instance.userObject.method})]`
  * [(#{report.alerts.detail.param})]: `[(${instance.userObject.param})]`
  * [(#{report.alerts.detail.attack})]: `[(${instance.userObject.attack})]`
  * [(#{report.alerts.detail.evidence})]: `[(${instance.userObject.evidence})]`
  * [(#{report.alerts.detail.otherinfo})]: `[(${instance.userObject.otherinfo})]`
[/th:block]
[#th:block th:if="${helper.isSystemic(alert)}"][(#{report.alerts.detail.instances})]: [(#{report.alerts.list.systemic})][/th:block]
[#th:block th:unless="${helper.isSystemic(alert)}"][(#{report.alerts.detail.instances})]: [(${alert.childCount})][/th:block]

### [(#{report.alerts.detail.solution})]

[(${alert.userObject.solution})]

### [(#{report.alerts.detail.reference})]

[#th:block th:each="ref: ${#strings.arraySplit(alert.userObject.reference, '\n')}"]
* [ [(${ref})] ]([(${ref})])
[/th:block]
[#th:block th:if="${alert.userObject.cweId > 0}"]
#### [(#{report.alerts.detail.cweid})]: [ [(${alert.userObject.cweId})] ](https://cwe.mitre.org/data/definitions/[(${alert.userObject.cweId})].html)
[/th:block]
[#th:block th:if="${alert.userObject.wascId > 0}"]
#### [(#{report.alerts.detail.wascid})]: [(${alert.userObject.wascId})]
[/th:block]
#### [(#{report.alerts.detail.sourceid})]: [(${alert.userObject.source.id})]
[/th:block]
[/th:block]
