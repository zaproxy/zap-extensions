description = "OAST Support: Exploit Out-Of-Band Vulnerabilities"

zapAddOn {
    addOnName.set("OAST Support")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/oast-support/")
    }

    apiClientGen {
        api.set("org.zaproxy.addon.oast.OastApi")
        options.set("org.zaproxy.addon.oast.OastParam")
        messages.set(file("src/main/resources/org/zaproxy/addon/oast/resources/Messages.properties"))
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    compileOnly("org.zaproxy:zap:2.11.0-SNAPSHOT")
}
