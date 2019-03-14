try:
    import os
    from bs4 import BeautifulSoup
    import os.path
    import argparse
    import sys
    import codecs

except ImportError:
    print "[!] wrong installation detected (missing modules)."
    exit()


def banner():
    print " "
    print " #######################################################################"
    print " #                                                                     #"
    print " #  \______   \    |   \______   \______   \ \__    ___/\_____  \      #"
    print " #   |    |  _/    |   /|       _/|     ___/   |    |    /   |   \     #"
    print " #   |    |   \    |  / |    |   \|    |       |    |   /    |    \    #"
    print " #   |______  /______/  |____|_  /|____|       |____|   \_______  /    #"
    print " #          \/                 \/                               \/     #"
    print " #    _________________  .____       _____      _____ __________       #"
    print " #   /   _____/\_____  \ |    |     /     \    /  _  \\\______   \      #"
    print " #   \_____  \  /  / \  \|    |    /  \ /  \  /  /_\  \|     ___/      #"
    print " #   /        \/   \_/.  \    |___/    Y    \/    |    \    |          #"
    print " #  /_______  /\_____\ \_/_______ \____|__  /\____|__  /____|          #"
    print " #          \/        \__>       \/       \/         \/                #"
    print " #                                                                     #"
    print " #    Created By: Milad Khoshdel      Blog: https://blog.regux.com     #"
    print " #                                    E-Mail: miladkhoshdel@gmail.com  #"
    print " #######################################################################"
    print " "


def usage():
    print" "
    print"  Usage: ./burp-to-sqlmap.py [options]"
    print"  Options: -f, --file               <BurpSuit State File>"
    print"  Options: -o, --outputdirectory    <Output Directory>"
    print"  Options: -s, --sqlmappath         <SQLMap Path>"
    print"  Options: -p, --proxy              <Use Proxy>"
    print"  Example: python burp-to-sqlmap.py -f [BURP-STATE-FILE] -o [OUTPUT-DIRECTORY] -s [SQLMap-Path] -p [Proxy]"
    print" "

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file")
    parser.add_argument("-o", "--outputdirectory")
    parser.add_argument("-s", "--sqlmappath")
    parser.add_argument("-p", "--proxy")
    args = parser.parse_args()

    if not args.file or not args.outputdirectory or not args.sqlmappath:
        banner()
        usage()
        sys.exit(0)

    if args.proxy:
        proxyvalue = "--proxy " + args.proxy
    else:
        proxyvalue = ""


    vulnerablefiles = []
    banner()
    filename = args.file
    directory = args.outputdirectory
    sqlmappath = args.sqlmappath
    if not os.path.exists(directory):
        os.makedirs(directory)

    if sys.platform.startswith("win32"):
        runWindows(filename, directory, sqlmappath, proxyvalue, vulnerablefiles)
    elif sys.platform.startswith("linux"):
        runLinux(filename, directory, sqlmappath, proxyvalue, vulnerablefiles)
    else:
        print "[+] Error: Unsupported OS Detected!"

def runWindows(filename, directory, sqlmappath, proxyvalue, vulnerablefiles):
    packetnumber = 0
    print " [+] Exporting Packets ..."
    with open(filename, 'r') as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        for i in soup.find_all("request"):
            packetnumber = packetnumber + 1
            print "   [-] Packet " + str(packetnumber) + " Exported."
            outfile = open(os.path.join(args.outputdirectory, str(packetnumber) + ".txt"), "w")
            outfile.write(i.text.strip())
        print " "
        print str(packetnumber) + " Packets Exported Successfully."
        print " "

    print " [+] Testing SQL Injection on packets ...  (Based on your network connection Test can take up to 5 minutes.)"
    for file in os.listdir(directory):
        print "   [-] Performing SQL Injection on packet number " + file[:-4] + ". Please Wait ..."
        os.system("python " + sqlmappath + "\sqlmap.py -r " + os.path.dirname(os.path.realpath(
            __file__)) + "\\" + directory + "\\" + file + " --batch " + proxyvalue + " > " + os.path.dirname(
            os.path.realpath(__file__)) + "\\" + directory + "\\testresult" + file)
        if 'is vulnerable' in open(directory + "\\testresult" + file).read() or "Payload:" in open(
                directory + "\\testresult" + file).read():
            print "    - URL is Vulnerable."
            vulnerablefiles.append(file)
        else:
            print "    - URL is not Vulnerable."
        print "    - Output saved in " + directory + "\\testresult" + file
    print " "
    print "--------------"
    print "Test Done."
    print "Result:"
    if not vulnerablefiles:
        print "No vulnerabilities found on your target."
    else:
        for items in vulnerablefiles:
            print "Packet " + items[:-4] + " is vulnerable to SQL Injection. for more information please see " + items
    print "--------------"
    print " "

def runLinux(filename, directory, sqlmappath, proxyvalue, vulnerablefiles):
    packetnumber = 0
    print " [+] Exporting Packets ..."
    
    with open(filename, 'r') as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        for i in soup.find_all("request"):
            packetnumber = packetnumber + 1
            print "   [-] Packet " + str(packetnumber) + " Exported."
            outfile = codecs.open(os.path.join(directory, str(packetnumber) + ".txt"), "w", "utf-16le")
            outfile.write(i.text.strip())
        print " "
        print str(packetnumber) + " Packets Exported Successfully."
        print " "

    print " [+] Testing SQL Injection on packets ...  (Based on your network connection Test can take up to 5 minutes.)"
    for file in os.listdir(directory):
        #The following few lines solves an issue with the character encoding.
        #Burp in Kali exports the HTTP history as UTF-16LE which was resulting
        #in the individual request files not being read successfully by sqlmap
        #There is probably a cleaner way to do this.
        cmd = "iconv -f utf-16le -t ascii %s > %s_ascii" % (os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file,os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file)
        os.system(cmd)
        cmd = "cat %s_ascii > %s" % (os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file,os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file)
        os.system(cmd)
        cmd = "rm %s_ascii" % (os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file)
        os.system(cmd)
        print "   [-] Performing SQL Injection on packet number " + file[:-4] + ". Please Wait ..."
        cmd = "python " + sqlmappath + "/sqlmap.py -r " + os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file + " --batch " + proxyvalue + " > " + os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/testresult" + "_" + file
        os.system(cmd)
        if 'is vulnerable' in open(directory + "/testresult" + "_" + file).read() or "Payload:" in open(
                directory + "/testresult" + "_" + file).read():
            print "    - URL is Vulnerable."
            vulnerablefiles.append(file)
        else:
            print "    - URL is not Vulnerable."
        print "    - Output saved in " + directory + "/testresult" + file
        print " "
        print "--------------"
        print "Test Done."
        print "Result:"
        if not vulnerablefiles:
            print "No vulnerabilities found on your target."
        else:
            for items in vulnerablefiles:
                 print "Packet " + items[:-4] + " is vulnerable to SQL Injection. for more information please see " + items
        print "--------------"
        print " "


if __name__ == "__main__":
    main()
