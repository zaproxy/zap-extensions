import org.zaproxy.gradle.addon.AddOnStatus

version = "14"
description = "An advanced active injection bundle for SQLi (derived by SQLMap)"

zapAddOn {
    addOnName.set("Advanced SQLInjection Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.5.0")

    manifest {
        author.set("Andrea Pompili (Yhawke)")
    }
}

dependencies {
    implementation("org.jdom:jdom:1.1.3")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf(
        "**/DBMSHelper.java",
        "**/SQLiBoundary.java",
        "**/SQLInjectionPlugin.java",
        "**/SQLiPayloadManager.java",
        "**/SQLiTest.java",
        "**/SQLiTestDetails.java",
        "**/SQLiTestRequest.java",
        "**/SQLiTestResponse.java",
        "**/SQLiUnionEngine.java"))
}
