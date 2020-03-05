version = "3"
description = "Alert reports using BIRT report API"

zapAddOn {
    addOnName.set("BIRT Reports")
    zapVersion.set("2.9.0")

    manifest {
        author.set("Johanna Curiel And Rauf Butt")
        url.set("https://www.zaproxy.org/docs/desktop/addons/birt-reports/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        bundledLibs {
            libs.from(configurations.runtimeClasspath)
        }
    }
}

dependencies {
    implementation("org.eclipse.birt.runtime:org.eclipse.birt.runtime:4.2.2")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("**/ReportLastScan.java"))
}
