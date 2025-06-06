clang -o pie test.c -fPIE
clang -o arc_and_canary obj_c_prog.m -fobjc-arc -framework Foundation -fstack-protector-strong

