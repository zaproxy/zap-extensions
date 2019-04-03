import org.zaproxy.gradle.addon.AddOnStatus

version = "15"
description = "Allows you to generate reports for alerts you specify in pdf or odt format"

zapAddOn {
    addOnName.set("Report alert generator")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.5.0")

    manifest {
        author.set("Talsoft SRL")
        url.set("http://www.talsoft.com.ar")
    }
}

configurations {
    "implementation" {
        // Not needed.
        exclude(group = "org.apache.odftoolkit", module = "taglets")
    }
}

dependencies {
    implementation ("org.apache.pdfbox:pdfbox:1.8.7") {
        // Provided by ZAP.
        exclude(group = "commons-logging")
        // Not needed.
        exclude(group = "org.apache.pdfbox", module = "jempbox")
    }
    implementation ("org.apache.odftoolkit:simple-odf:0.7-incubating")
    implementation ("org.apache.odftoolkit:xslt-runner:1.2.1-incubating")
}
