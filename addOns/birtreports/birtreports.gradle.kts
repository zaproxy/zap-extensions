version = "3"
description = "Alert reports using BIRT report API"

zapAddOn {
    addOnName.set("birtreports")
    zapVersion.set("2.5.0")

    manifest {
        author.set("Johanna Curiel And Rauf Butt")
        // Don't search the add-on classes (for now), the Extensions do not work properly:
        // https://github.com/zaproxy/zaproxy/issues/2235
        classpath.setFrom(files())
    }
}

dependencies {
    implementation("org.eclipse.birt.runtime:org.eclipse.birt.runtime:4.2.2")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("**/ReportLastScan.java"))
}
