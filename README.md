Run the makefile:
  $ make
You will be prompted for a name or initials. This is the identifier for your key set and will be used to individualize your files and executable name.

The makefile will create a subdirectory called "crypt-xyz" where xyz is your chosen key identifier. Inside of that directory you will find the file "encrypt4_xyz_remote.c". This is the source file for the executable that will allow your remote user to send encrypted files to you. Change the name of this file to "encrypt4_xyz.c" or whatever you like, and send that file and the instructions.txt file to your remote user. They will then need to compile the file. Once they compile it, they can use it to encrypt files and send the encrypted files to you. The encrypted files will normally have an ".xyz" extension indicating that they are encrypted with the public key known as "xyz". When you receive such a file you can decrypt it with the decrypt binary in your output subdirectory as follows:

  $ decrypt4_xyz user-sent-file.xyz

  
