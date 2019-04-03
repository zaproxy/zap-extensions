version = "5"
description = "Allows you to import log files from ModSecurity and files previously exported from ZAP"

zapAddOn {
    addOnName.set("Log File Importer")
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://github.com/zaproxy/zaproxy/wiki/MozillaMentorship_ImportingModSecurityLogs")
    }
}

dependencies {
    implementation(files("lib/org.jwall.web.audit-0.2.15.jar"))
}
