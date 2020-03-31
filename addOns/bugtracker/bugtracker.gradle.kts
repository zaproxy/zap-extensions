version = "3"
description = "Bug Tracker extension."

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror" + "-proc:none"
}

repositories {
    // Required by dependencies of org.kohsuke:github-api:1.75.
    maven(url = "https://repo.jenkins-ci.org/releases/")
}

zapAddOn {
    addOnName.set("Bug Tracker")
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/bug-tracker/")
    }
}

dependencies {
    implementation("com.j2bugzilla:j2bugzilla:2.2.1") {
        // Not needed.
        exclude(group = "junit")
    }
    implementation("org.kohsuke:github-api:1.75") {
        // Not needed.
        exclude(group = "com.infradna.tool")
        // Provided by ZAP.
        exclude(group = "commons-codec")
        // Provided by ZAP.
        exclude(group = "commons-io")
    }
}
