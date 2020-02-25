// Build tweaks when running in Travis CI

fun isEnvVarTrue(envvar: String) = System.getenv(envvar) == "true"

if (isEnvVarTrue("TRAVIS") && isEnvVarTrue("CI")) {

    allprojects {
        tasks.withType(Test::class).configureEach {
            testLogging {
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }

}