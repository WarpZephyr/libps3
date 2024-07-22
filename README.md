# libps3
A library written in C# for processing certain PS3 things such as PS3 specific files.  
Currently supports:  
- PARAM.SFO reading  
- PARAM.SFO Writing (UNTESTED)  
- SDAT decryption  
- EDAT decryption (UNTESTED)  
- SDAT and EDAT decompression (UNTESTED and slightly sketchy in implementation)
- RAP to RIF conversion

# Building
If you want to build the project you should clone it with these commands in git bash in a folder of your choosing:  
```
git clone https://github.com/WarpZephyr/BinaryMemory.git  
git clone https://github.com/WarpZephyr/libps3.git  
```
Dependencies are subject to possibly change if improvements are made or they are better standardized.