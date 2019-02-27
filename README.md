# BearerAuthToken

This burpsuite extender provides a solution on testing Enterprise applications that involve security Authorization tokens into every HTTP requests.Furthermore, this solution provides a better approach to solve the problem of Burp suite automated scanning failures when Authorization tokens exist.

## installation information  

You can download the BearerToken.jar and install it directly to your BurpSuite or alternativey if you want to compile and create the jar yourself follow the steps below : 

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1) clone this repo 
2) unzip burp.zip file 
3) change directory to burp subfolder 
4) inside burp subfolder compile the java files using the following command --> *javac *.java* 
5) if you get the following message "Some input files use unchecked or unsafe operations" recompile with --> **javac -Xlint:unchecked *.java**
6) When finished compiling go back one folder -> cd .. 
7) be sure that you are at the same folder where the burp subfolder exists
8) use the following command to create the jar file --> *jar cf burpextender.jar burp* 
9) install it to BurpSuite 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

for more information on how to use this extension follow the link https://www.twelvesec.com/2017/05/05/authorization-token-manipulation/
