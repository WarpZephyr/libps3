# libps3
A library written in C# for processing certain PS3 things such as PS3 specific files.  
Currently supports:  
- PARAM.SFO reading  
- PARAM.SFO Writing (UNTESTED)  
- SDATA decryption  
- EDATA decryption (NOT FULLY TESTED)  
- SDATA and EDATA decompression (UNTESTED)  
- RAP to RIF conversion  

# Note
Much of the EDATA code is adapted from make_npdata's C++ to C#.  
The code has been largely rewritten to my liking, but it is still learned from make_npdata.  
Parts of the NPD cryptography code are used in EDATA and are similarly adapted.
The decompression code is currently still adapted from RPCS3 but is untested.  
Most of the decompression code is using pointers.  
For licensing regarding the use of this code, refer to make_npdata and RPCS3 respectively.  

# Building
If you want to build the project you should clone it with these commands in git bash in a folder of your choosing:  
```
git clone --recursive https://github.com/WarpZephyr/libps3.git  
```
Dependencies are subject to possibly change if improvements are made or they are better standardized.