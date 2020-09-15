# kcorehpyc 
## (Its encrypted! :grin: )

- [Task 1](https://github.com/Aman333Saxena/kcorehpyc/blob/master/first.c)
  
  First, converted Hexadecimal String to Byte Array.
Then Distributed the byte array into unsigned_txn struct data type
Considered even length input string, odd length string can be first operated by inserting '0' at the begining and then using the same method as used above.

- [Task 2](https://github.com/Aman333Saxena/kcorehpyc/tree/master/second)

  - [MakeFile](https://github.com/Aman333Saxena/kcorehpyc/blob/master/second/MakeFile):
  
    Created a Makefile in crypto Folder to automate compiling and execution of all the C files in the crypto folder and additional entropy file. Used basic makefile syntax considering the dependency tree having the header and external dependency files. First all the files are compiled and then converted in to object code before final execution. The makefile has features to check recursively in the dependency tree if there is need to compile a previously compiled file or not. If the file is modified currently then it compiles it again else it skips the step.  

  - [Calculate Entropy](https://github.com/Aman333Saxena/kcorehpyc/blob/master/second/main.c)
  
    Completed the given functional signature to calculate the entropy of the given mnemonic. The given mnemonic consists of 24 phrases. First, we check if the basic conditions are fulfilled or not. Then we find the actual position of each phares in the Word List provided in the additional header file. After finding the index we convert it into the byte codes and return the final entropy value of the mnemonic.  
