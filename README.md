#Form Grabber

Form grabber is a method of capturing web form data. 
This project is the result of a school research project and a proof of concept.

It should not be used for malicious purposes !

Happy learning.

## How to test it

0. Install and open the latest stable Firefox web browser.
1. Install and run Fiddler 2: http://www.fiddler2.com/fiddler2/
2. [OPTIONAL] download and run an echo server: http://bansky.net/echotool/. Run: echotool.exe localhost /p tcp /s 80
2. Create a new Visual Studio 2010 Project from source src/main.c.
3. Build and run the executable in RELEASE mode.
4. In Firefox, go to gmail.com. Verify you are in HTTPS mode.
5. Fill the login form (mail and password).
6. Click on the Log in button.
7. In Fiddler, textView mode, you should now see at least two requests. One encrypted to accounts.google.com. The other one unencrypted to localhost/postDemo.php.
   Inside the the POST data you'll find your email and password Email=myGmailMail@gmail.com&Passwd=guessMe&
8. [OPTIONAL] the echotool will print the content of the unencrypted POST. 

## How it could work

0. The form grabber is hidden on a corrupted and malicious PDF file.
1. The user opens the PDF file on a windows machine.
2. His machine gets infected : Hidden code on the PDF file is exectued..
3. The malicious code injects some code on the firefox process by using the well known CreateRemoteThread & WriteProcessMemory technique.
See [this page] (http://www.codeproject.com/Articles/4610/Three-Ways-to-Inject-Your-Code-into-Another-Proces#section_3) for more info about this technique

   a. It injects a "POST parser" on the firefox's PR_Write method.
   This parser detects when a HTTP POST command is sent and grabs login and passwords.
   
   b. It sends the information to a remote server
   
 This proof of concept offers some similar functionnalities to those offered by the zeus trojan : http://www.secureworks.com/research/threats/zeus/

## DOCS

0. CreateRemoteThread function : http://msdn.microsoft.com/en-us/library/windows/desktop/ms682437(v=vs.85).aspx
1. WriteProcessMemory function : http://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx
2. PR_Write function : https://developer.mozilla.org/en/PR_Write
3. Windows 7 UAC code-injection vulnerability (still unpatched ???): http://www.istartedsomething.com/20090613/windows-7-uac-code-injection-vulnerability-video-demonstration-source-code-released/