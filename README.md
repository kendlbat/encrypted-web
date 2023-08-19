# Encrypted Web file hosting
This project exists in order to enable easy access to personal files from any endpoint.  

The files are encrypted BEFORE being checked in by Git, so no trust is required in any third party.  
A **VERY** secure password should be used to access the files, as a weak password may be bruteforced rather quickly.  
Remember: These files are publicly accessible (at least the encrypted version), so maybe don't use this to store your passwords.  
Disclaimer: The encrypted files are able to be downloaded and bruteforced at a later date, just keep that in mind.  

The file encryption program also adds a so-called "pepper" to your password, which means that a random string gets appended to your password. This is an attempt to make the files a little more secure.
