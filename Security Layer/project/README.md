DESIGN CHOICE:
I chose to use the starter file provided by TA, so it helped me alot in term of structuring my code. I just followed the specfications and definition of functions that haved been provided. I guessed the rest is just implementing the logic.
I used to helper functions construct_TLV() and parse_TLV() to help me form or unwind the message.
In order to constructing TLV and parsing TLV, I used an variable to keep track of where I were in the message, so I knew where to add another TLV or extract a TLV. Whenever adding or extracting a TLV, I decremented or incremented this variable for the next use.
PROBLEMS:
Compiler could not able to find openssl library. Thanks to people on Campuswire, I learned how to troubleshoot this problem by basically creating a flag to point compiler to where to get the openssl library.
I forgot to put the keys in the same directory with executable files.
I did not specify the size of arrays I used to store lengths or data. As a result, compiler automatically allocated just a small amount of memory, and it had not enough spaces to store data, and it caused segmentation fault, so I had to specified these sizes.
I could not verify that the client's nonce signature was signed by server, and I got stuck at figuring out what went wrong for a very long time. Finally, I realized I had not loaded the server's private key, that was why the verify() returned false.
HMAC digest did not match with MAC data, and this caused me a significant time to debug. Finally, I realized that instead of using the max size of ciphertext to count the size of HMAC, i should use the actual size of ciphertext,

