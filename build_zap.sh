./gradlew :addOns:fuzz:spotlessApply

./gradlew :addOns:fuzz:build

python3 reload_fuzz_extension.py

