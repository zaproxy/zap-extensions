import org.zaproxy.gradle.addon.AddOnStatus

version = "14"
description = "An advanced active injection bundle for SQLi (derived by SQLMap)"

zapAddOn {
    addOnName.set("Advanced SQLInjection Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.10.0")

    manifest {
        author.set("Andrea Pompili (Yhawke)")
        url.set("https://www.zaproxy.org/docs/desktop/addons/advanced-sqlinjection-scanner/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

dependencies {
    implementation("org.jdom:jdom:2.0.2")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf(
        "src/**/DBMSHelper.java",
        "src/**/SQLiBoundary.java",
        "src/**/SQLInjectionScanRule.java",
        "src/**/SQLiPayloadManager.java",
        "src/**/SQLiTest.java",
        "src/**/SQLiTestDetails.java",
        "src/**/SQLiTestRequest.java",
        "src/**/SQLiTestResponse.java",
        "src/**/SQLiUnionEngine.java"))
}
