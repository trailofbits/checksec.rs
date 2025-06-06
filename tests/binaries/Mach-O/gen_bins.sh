clang -o basic src/test.c
clang -o arc_enabled src/obj_c_prog.m -fobjc-arc -framework Foundation
clang -fno-stack-protector -o no_canary src/test.c
clang -o nosig src/test.c && codesign --remove-signature ./nosig


