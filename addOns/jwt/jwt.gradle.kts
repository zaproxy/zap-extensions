version = "1"
description = "Detect, Show, Edit, Fuzz JWT requests"

zapAddOn {
    addOnName.set("JWT Extension")
    zapVersion.set("2.8.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("org.json:json:20190722")
    //https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt
    implementation("com.nimbusds:nimbus-jose-jwt:8.3")
    implementation(project(":addOns:fuzz"))
    implementation(project(":sharedutils"))
}
