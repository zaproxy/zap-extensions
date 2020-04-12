import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Detect JWT requests and scan them to find the vulnerabilities"

zapAddOn {
    addOnName.set("JWT Extension")
    zapVersion.set("2.9.0")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("KSASAN preetkaran20@gmail.com")
    }
}

dependencies {
    implementation("org.json:json:20190722")
    // https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt
    implementation("com.nimbusds:nimbus-jose-jwt:8.3")
    implementation(project(":sharedutils"))
}
