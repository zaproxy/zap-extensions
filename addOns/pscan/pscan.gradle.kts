import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides core passive scanning capabilities."

zapAddOn {
    addOnName.set("Passive Scanner")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scanner/")

        helpSet {
            baseName.set("org.zaproxy.addon.pscan.help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.pscan.PassiveScanApi")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}
