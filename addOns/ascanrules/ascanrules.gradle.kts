import org.zaproxy.gradle.addon.AddOnStatus

version = "37"
description = "The release quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/")
    }
}

dependencies {
    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
    implementation("org.bitbucket.mstrobel:procyon-compilertools:0.5.36")

    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(project, listOf(
        "**/BufferOverflowScanRule.java",
        "**/CrlfInjectionScanRule.java",
        "**/DirectoryBrowsingScanRule.java",
        "**/FormatStringScanRule.java",
        "**/ParameterTamperScanRule.java",
        "**/ServerSideIncludeScanRule.java"))
}
