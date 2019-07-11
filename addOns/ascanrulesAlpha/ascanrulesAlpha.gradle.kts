version = "26"
description = "The alpha quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (alpha)")
    zapVersion.set("2.6.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://github.com/zaproxy/zap-extensions/wiki/HelpAddonsAscanrulesAlphaAscanalpha")
    }
}

dependencies {
    implementation("org.jsoup:jsoup:1.7.2")
}
