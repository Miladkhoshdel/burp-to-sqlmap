# Welcome to Burp-to-SQLMap

As you know, SQL Injection is a security vulnerability with critical severity. If you are a hacker you know it as well that it takes a lot of times to find a sql injection vulnerability on a target. It will be worse if you are a penetration tester. You must check this vulnerability on all of  target URLs by intercepting packets using Burp Suit or other tools and in big Portals it’s not easy.

I have good news for hackers and pen testers. I made it easier by my new python script. The only thing you should do, is exporting your packets as a burp suit state file. The rest of steps will done by my script. I called me script “Burp-TO-SQLMap” and I will explain the test process from the beginning.


# Usage

>  Usage: ./burp-to-sqlmap.py [options]
>  
>  Options: -f, --file               <BurpSuit State File>
>  
>  Options: -o, --outputdirectory    <Output Directory>
>  
>  Options: -s, --sqlmappath         <SQLMap Path>
>  
>   Options: -p, --proxy              <Use Proxy>
>  
>   Options: -r, --risk               <Use Proxy>
>  
>   Options: -l, --level              <Use Proxy>
>  
>   Example: python burp-to-sqlmap.py -f [BURP-STATE-FILE] -o [OUTPUT-DIRECTORY] -s [SQLMap-Path] -p [Proxy] -r 3 -l 5

- Vulnerable Packet Result

![Create Request/Response File](https://raw.githubusercontent.com/Miladkhoshdel/burp-to-sqlmap/master/4.PNG)



# How to Create Request/Response File in BurpSuite

1) Select Your Request

![Create Request/Response File](https://raw.githubusercontent.com/Miladkhoshdel/burp-to-sqlmap/master/1.PNG)


2) Right Clicke one one of these selected requests

![Create Request/Response File](https://raw.githubusercontent.com/Miladkhoshdel/burp-to-sqlmap/master/2.PNG)


3) Uncheck Base64 Option and create your requests/responses file

![Create Request/Response File](https://raw.githubusercontent.com/Miladkhoshdel/burp-to-sqlmap/master/3.PNG)


