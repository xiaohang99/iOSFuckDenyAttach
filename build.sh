xcrun -sdk iphoneos clang -arch arm64 -Wall -O3 -o fda fda.c find_kernel_base_under_checkra1n.c
codesign -s - --entitlements ent.plist fda