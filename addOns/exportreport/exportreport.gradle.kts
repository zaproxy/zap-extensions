version = "6"
description = "Report Export module that allows users to customize content and export in a desired format."

zapAddOn {
    addOnName.set("Export Report")
    zapVersion.set("2.7.0")

    manifest {
        author.set("Goran Sarenkapa - JordanGS")
    }
}

dependencies {
    implementation("org.json:json:20160212")
    implementation("org.glassfish.jaxb:jaxb-runtime:2.3.2")
}
