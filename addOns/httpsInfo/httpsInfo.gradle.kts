version = "13"
description = "Displays HTTPS configuration information."

zapAddOn {
    addOnName.set("HttpsInfo")
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/https-info-add-on/")
    }
}

dependencies {
    implementation("com.github.spoofzu:DeepViolet:5.1.16")
    implementation("org.slf4j:slf4j-log4j12:1.7.6") {
        // Provided by ZAP.
        exclude(group = "log4j")
    }
}
