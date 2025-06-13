# libps3
A library written in C# for processing certain PS3 things such as PS3 specific files.  
Currently supports:  
- PARAM.SFO reading  
- PARAM.SFO Writing (UNTESTED)  
- SDAT decryption  
- EDAT decryption (UNTESTED)  
- SDAT and EDAT decompression (UNTESTED)  
- RAP to RIF conversion  

# Note
Much of the EDAT code is adapted from RPCS3's C++ to C#.  
The decompression code is also adapted from there but is untested.  
Most of the decompression code is using pointers.  
For licensing regarding the use of that code, refer to RPCS3 and its licensing use of that code.  

# Building
If you want to build the project you should clone it with these commands in git bash in a folder of your choosing:  
```
git clone https://github.com/WarpZephyr/Edoke.git  
git clone https://github.com/WarpZephyr/libps3.git  
```
Dependencies are subject to possibly change if improvements are made or they are better standardized.