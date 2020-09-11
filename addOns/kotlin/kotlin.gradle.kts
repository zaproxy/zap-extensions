import org.zaproxy.gradle.addon.AddOnStatus

version = "1.0.0"
description = "Allows Kotlin to be used for ZAP scripting"

zapAddOn {
    addOnName.set("Kotlin Support")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("StackHawk Engineering")
        url.set("https://www.zaproxy.org/docs/desktop/addons/kotlin-support/")
    }
}

dependencies {
    val ktVersion = "1.3.72"
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8:$ktVersion")
    implementation("org.jetbrains.kotlin:kotlin-scripting-jsr223-embeddable:$ktVersion")
    implementation("org.jetbrains.kotlin:kotlin-compiler-embeddable:$ktVersion")

    testImplementation(project(":testutils"))
}
