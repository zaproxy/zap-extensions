import org.zaproxy.gradle.addon.AddOnStatus

version = "39"
description = "The release quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/")
        notBeforeVersion.set("2.10.0")

        dependencies {
            addOns {
                register("commonlib")
            }
        }
    }
}

repositories {
    maven {
        url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
    }
}

dependencies {
    zap("org.zaproxy:zap:2.10.0-20201111.162919-2")

    compileOnly(parent!!.childProjects.get("commonlib")!!)
    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
    implementation("org.bitbucket.mstrobel:procyon-compilertools:0.5.36")

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
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
