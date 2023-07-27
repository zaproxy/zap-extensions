import org.zaproxy.gradle.addon.AddOnStatus

description = "An advanced active injection bundle for SQLi (derived by SQLMap)"

zapAddOn {
    addOnName.set("Advanced SQLInjection Scanner")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("Andrea Pompili (Yhawke)")
        url.set("https://www.zaproxy.org/docs/desktop/addons/advanced-sqlinjection-scanner/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.5.0 & < 2.0.0")
                }
            }
        }
    }
}

crowdin {
    configuration {
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    zapAddOn("commonlib")

    implementation("org.jdom:jdom:2.0.2")
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/DBMSHelper.java",
            "src/**/SQLiBoundary.java",
            "src/**/SQLInjectionScanRule.java",
            "src/**/SQLiPayloadManager.java",
            "src/**/SQLiTest.java",
            "src/**/SQLiTestDetails.java",
            "src/**/SQLiTestRequest.java",
            "src/**/SQLiTestResponse.java",
            "src/**/SQLiUnionEngine.java",
        ),
    )
}
