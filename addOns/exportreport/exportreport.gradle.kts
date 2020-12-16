version = "8"
description = "Report Export module that allows users to customize content and export in a desired format."

zapAddOn {
    addOnName.set("Export Report")
    zapVersion.set("2.9.0")

    manifest {
        author.set("Goran Sarenkapa - JordanGS")
        url.set("https://www.zaproxy.org/docs/desktop/addons/export-report/")
        notBeforeVersion.set("2.10.0")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.exportreport.ExportReportAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/exportreport/resources/Messages.properties"))
    }
}

dependencies {
    implementation("org.json:json:20160212")
    implementation("org.glassfish.jaxb:jaxb-runtime:2.3.2")
    implementation("org.apache.pdfbox:pdfbox:1.8.7") {
        // Provided by ZAP.
        exclude(group = "commons-logging")
        // Not needed.
        exclude(group = "org.apache.pdfbox", module = "jempbox")
    }
}

spotless {
    java {
        target(fileTree(projectDir) {
            include("**/*.java")
            // 3rd-party code.
            exclude("**/utility/SpringUtilities.java")
        })
    }
}
