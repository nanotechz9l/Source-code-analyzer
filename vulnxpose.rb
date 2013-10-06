#!/usr/bin/env ruby
require 'rainbow'; require 'english'

=begin
#   :::$Id: vulnxpose.rb 6191 20nano $
#   :::Source k0de Analyzer koded by Nanotechz9l
#   :::zet Xterm to 102x24 for better reZUltSss./|
#   :::$Revision: 0.1 $
#
# c_rules file                           ref: http://www.dwheeler.com/flawfinder/
# Microsoft banned functions             ref: http://msdn.microsoft.com/en-us/library/bb288454.aspx
# Analyze file information               ref: http://redneckprogrammer.blogspot.com/2007/09/word-character-line-counter-ruby-script.html
# Line numbers courtesy of `the Tin Man` ref: http://stackoverflow.com/questions/19173408/how-do-i-print-the-line-number-of-the-file-i-am-working-with-via-argv
=end

def v() # TODO: make random at runtime at some point (like msf, and set... no biggie)
print """
'##::::'##:'##::::'##:'##:::::::'##::: ##:'##::::'##:'########:::'#######:::'######::'########:
 ##:::: ##: ##:::: ##: ##::::::: ###:: ##:. ##::'##:: ##.... ##:'##.... ##:'##... ##: ##.....::
 ##:::: ##: ##:::: ##: ##::::::: ####: ##::. ##'##::: ##:::: ##: ##:::: ##: ##:::..:: ##:::::::
 ##:::: ##: ##:::: ##: ##::::::: ## ## ##:::. ###:::: ########:: ##:::: ##:. ######:: ######:::
. ##:: ##:: ##:::: ##: ##::::::: ##. ####::: ## ##::: ##.....::: ##:::: ##::..... ##: ##...::::
:. ## ##::: ##:::: ##: ##::::::: ##:. ###:: ##:. ##:: ##:::::::: ##:::: ##:'##::: ##: ##:::::::
::. ###::::. #######:: ########: ##::. ##: ##:::. ##: ##::::::::. #######::. ######:: ########:
:::...::::::.......:::........::..::::..::..:::::..::..::::::::::.......::::......:::........::
""".foreground(:red)
end

# Kreate the variable text
text =''

# TODO: Fix the no ARGV error :30: `readlines': no implicit conversion of nil into String (TypeError)
# File implements a readlines method that reads an entire file into an array line by line 
# You can use this both to count the lines and join them all into a single string
lines      = File.readlines(ARGV[0]) # or I could use ARGV.first which is the same thing :)
line_count = lines.size
text       = lines.join
v()

if not ARGV[0]
 print "\nMISSING input file!".foreground(:red).bright
 print "\nUsage: #{$0} vulnfile.c\n\n".foreground(:white).bright
 exit(0)
 v()
end

# User greet!
puts "\n\tVULNXPOSE v0.1 written by ".foreground(:red) << "Rick <@nanotechz9l> Flores".foreground(:white)
puts "\tI scan .C source files for known dangerous/banned functions, & calculate an overall security score.".foreground(:red)

# Initialize variables to default values // ref: redneckprogrammer
results = []
words   = 0
chars   = 0
minline = 0
maxline = 0
filename = ARGV[0]

File.new(filename, "r").each { |line| results << line }

puts "\n\nNumber of dangerous functions in C/C++ ruleset: 160" #+ "#{dfuncs.count}" Fix this so the number of functions is dynamically shown at runtime.
puts "\nStep 1/3:".foreground(:white).underline.bright << " Gathering basic file information from #{filename}...".foreground(:cyan)
puts "#{filename} has the following attributes:"
puts " -> #{results.size} lines."

results.each do |line|
 chars += line.length
 words += line.split.length
 
 if line.length > maxline then
  maxline = line.length
 elsif line.length < minline then
  minline = line.length
   end
 end

puts " -> #{words} words."
puts " -> #{chars} characters."
puts " -> #{minline} character shortest line length."
puts " -> #{maxline} characters longest line length." # -- end of redneckprogrammer code

# Start analyzing source file for security vulns
# Note that since a block is given, file will automatically be closed when the block terminates
# TODO: Insert all 160 functions from flawfinder!
puts "\nStep 2/3:".foreground(:white).underline.bright << " Starting security analysis on #{filename}...".foreground(:cyan)

# File.open(ARGV[0]) do |f|
#    f.each_line do |line|
 File.foreach(ARGV[0]) do |line|
   
    if line.match(
       /(strcpy)/i) # i makes regex case insensitive // test.c:66:  [1] (buffer) MultiByteToWideChar:
       puts "[!] strcpy does not check for buffer overflows when copying to destination.".foreground(:yellow).bright
       puts "[!] Consider using strncpy or strlcpy (warning, strncpy is easily misused).".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
    
    if line.match(
       /(lstrcpy|wcscpy|_tcscpy|_mbscpy)/i)
       puts "[!] This function does not check for buffer overflows when copying to destination.".foreground(:yellow).bright
       puts "[!] Consider using a function version that stops copying at the end of the buffer.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
    
    if line.match(
       /(memcpy|CopyMemory|bcopy)/i) # flawfinder author found this to have a lower risk in practice.
       puts "[!] This function does not check for buffer overflows when copying to destination.".foreground(:yellow).bright
       puts "[!] Make sure destination can always hold the source data.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end

    if line.match(
       /(strcat)/i)
       puts "[!] strcat does not check for buffer overflows when copying to destination.".foreground(:yellow).bright
       puts "[!] Consider using strncat or strlcat (warning, strncat is easily misused).".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match(
       /(lstrcat|wcscat|_tcscat|_mbscat)/i)
       puts "[!] These functions do not check for buffer overflows when concatenating to destination.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match(
       /(strncpy)/i) # Low risk level, because this is often used correctly when FIXING security
                     # problems, and raising it to a higher risk level would cause many false positives.
       puts "[!] Easily used incorrectly; doesn't always \\0-terminate or check for invalid pointers.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match(
       /(lstrcpyn|wcsncpy|_tcsncpy|_mbsnbcpy)/i) # Low risk level, because this is often used correctly when FIXING security
                                                 # problems, and raising it to a higher risk level would cause many false positives.
       puts "[!] Easily used incorrectly; doesn't always \\0-terminate or check for invalid pointers.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match(
       /(strncat)/i) # Low risk level, because this is often used correctly when FIXING security
                    # problems, and raising it to a higher risk level would cause many false positives.
       puts "[!] Easily used incorrectly (e.g., incorrectly computing the correct maximum size to add.".foreground(:yellow).bright
       puts "[!] Consider strlcat or automatically resizing strings.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match(
       /(lstrcatn|wcsncat|_tcsncat|_mbsnbcat)/i) # Low risk level, because this is often used correctly when FIXING security
                                                 # problems, and raising it to a higher risk level would cause many false positives.
       puts "[!] Easily used incorrectly (e.g., incorrectly computing the correct maximum size to add.".foreground(:yellow).bright
       puts "[!] Consider strlcat or automatically resizing strings.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match(
       /(strccpy|strcadd)/i)
       puts "[!] Subject to buffer overflow if buffer is not as big as claimed.".foreground(:yellow).bright
       puts "[!] Ensure that destination buffer is sufficiently large.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match(
       /(char|TCHAR|wchar_t)/i) # This isn't really a function call, but it works.
       puts "[!] Statically-sized arrays can be overflowed. Perform bounds checking, use functions that limit length,".foreground(:yellow).bright
       puts "[!] or ensure that the size is larger than the maximum possible length.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end

    if line.match(
       /(gets|_getts)/i)
       puts "[!] Does not check for buffer overflows.".foreground(:yellow).bright
       puts "[!] Use snprintf or vsnprintf instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match(
       /(sprintf|vsprintf|swprintf|vswprintf|_stprintf|_vstprintf)/i) # The "sprintf" hook will raise "format" issues instead if appropriate:
       puts "[!] Does not check for buffer overflows.".foreground(:yellow).bright
       puts "[!] Use snprintf or vsnprintf instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
      # TODO: Add "wide character" versions of these functions.
    if line.match( 
       /(printf|vprintf|vwprintf|vfwprintf|_vtprintf|fprintf|vfprintf|_ftprintf|_vftprintf)/i)
       puts "[!] If format strings can be influenced by an attacker, they can be exploited.".foreground(:yellow).bright
       puts "[!] Use a constant for the format specification.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(syslog)/i)   # The "syslog" hook will raise "format" issues.
       puts "[!] If syslog's format strings can be influenced by an attacker, they can be exploited.".foreground(:yellow).bright
       puts "[!] Use a constant format string for syslog.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(snprintf|vsnprintf|_snprintf|_sntprintf|_vsntprintf)/i)
       puts "[!] If format strings can be influenced by an attacker, they can be exploited.".foreground(:yellow).bright
       puts "[!] and note that sprintf variations do not always \\0-terminate. Use a constant for the format specification".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(scanf|vscanf|wscanf|_tscanf)/i)
       puts "[!] The scanf() family's %s operation, without a limit specification permits buffer overflows.".foreground(:yellow).bright
       puts "[!] Specify a limit to %s, or use a different input function.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(fscanf|sscanf|vsscanf|vfscanf|_ftscanf)/i)
       puts "[!] The scanf() family's %s operation, without a limit specification permits buffer overflows.".foreground(:yellow).bright
       puts "[!] Specify a limit to %s, or use a different input function.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(strlen|wcslen|_tcslen|_mbslen)/i) # Often this isn't really a risk, and even when, it usually at worst causes program crash (and nothing worse).
       puts "[!] Does not handle strings that are not \\0-terminated (it could cause a crash if unprotected.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(MultiByteToWideChar)/i) # Windows. Only the default - this will be changed in many cases.
       puts "[!] Requires maximum length in CHARACTERS, not bytes.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end

    if line.match( 
       /(streadd|strecpy)/i)
       puts "[!] This function does not protect against buffer overflows.".foreground(:yellow).bright
       puts "[!] Ensure the destination has 4 times the size of the source, to leave room for expansion.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(strtrns)/i)
       puts "[!] This function does not protect against buffer overflows.".foreground(:yellow).bright
       puts "[!] Ensure the destination is atleast as long as the source.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(realpath)/i)
       puts "[!] This function does not protect against buffer overflows, and some implementations can overflow internally".foreground(:yellow).bright
       puts "[!] Ensure that the destination buffer is at least of size MAXPATHLEN, and".foreground(:yellow).bright
       puts "[!] to protect against implementation problems, the input argument should also be checked to ensure it is no larger than MAXPATHLEN".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(getopt|getopt_long)/i)
       puts "[!] Some older implementations do not protect against internal buffer overflows".foreground(:yellow).bright
       puts "[!] Check implementation on installation, or limit the size of all string inputs".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(getpass)/i)
       puts "[!] Some implementations of getpass may overflow buffers".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(getwd)/i)
       puts "[!] getwd does not protect against buffer overflows by itself, so use with caution. Use getcwd instead".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(getchar|fgetc|getc|read|_gettc)/i) # fread not included here; in practice I think it's rare to mistake it.
       puts "[!] Check buffer boundaries if used in a loop".foreground(:yellow).bright # loops may be via recursion, too.
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
       
    if line.match( 
       /(access)/i) # ???: TODO: analyze TOCTOU more carefully.
       puts "[!] This usually indicates a security flaw. If an attacker can change anything along the path between the call to access() and the file's actual use (e.g., by moving".foreground(:yellow).bright
       puts "files), the attacker can exploit the race condition. Set up the correct permissions (e.g., using setuid()) and try to open the file directly.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
       
    if line.match( 
       /(chown)/i)
       puts "[!] This accepts filename arguments; if an attacker can move those files, a race condition results. Use fchown( ) instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
       
    if line.match( 
       /(chgrp)/i)
       puts "[!] This accepts filename arguments; if an attacker can move those files, a race condition results. Use fchgrp( ) instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(chmod)/i)
       puts "[!] This accepts filename arguments; if an attacker can move those files, a race condition results. Use fchmod( ) instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(vfork)/i)
       puts "[!] On some old systems, vfork() permits race conditions, and it's very difficult to use correctly. Use fork() instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(readlink)/i) # This is often just a bad idea, and it's hard to suggest a simple alternative:
       puts "[!] This accepts filename arguments; if an attacker can move those files or change the link content, a race condition results. Also, it does not terminate with ASCII NUL.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(tmpfile)/i)
       puts "[!] Function tmpfile() has a security flaw on some systems (e.g., older System V systems)".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(tmpnam|tempnam)/i)
       puts "[!] Temporary file race conditions.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(mktemp)/i)   # TODO: Detect GNOME approach to mktemp and ignore it.
       puts "[!] Temporary file race conditions.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(mkstemp)/i)
       puts "[!] Potential for temporary file vulnerability in some circumstances. Some older Unix-like systems create temp files with permission to write by all by default, ".foreground(:yellow).bright
       puts "[!] so be sure to set the umask to override this. Also, some older Unix systems might fail to use O_EXCL when opening the file, so make sure that O_EXCL is used by the library.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(fopen|open)/i)
       puts "[!] Check when opening files - can an attacker redirect it (via symlinks), force the opening of special file type (e.g., device files), move things around to create a race condition, control its ancestors, or change its contents?".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(umask)/i)
       puts "[!] Ensure that umask is given the most restrictive possible setting (e.g., 066 or 077)".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(GetTempFileName)/i)   # Windows. TODO: Detect correct usage approaches and ignore it.
       puts "[!] Temporary file race condition in certain cases (e.g., if run as SYSTEM in many versions of Windows)".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(execl|execlp|execle|execv|execvp|system|popen|WinExec|ShellExecute)/i) # TODO: Need to detect varying levels of danger.
       puts "[!] This causes a new program to execute and is difficult to use safely try using a library call that implements the same functionality if available".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(CreateProcessAsUser|CreateProcessWithLogon)/i) # TODO: Be more specific. The biggest problem involves "first" param NULL, second param with embedded space. Windows.
       puts "[!] This causes a new process to execute and is difficult to use safely. Especially watch out for embedded spaces".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
   end
     
    if line.match( 
       /(CreateProcess)/i) # TODO: Be more specific. The biggest problem involves "first" param NULL, second param with embedded space. Windows.
       puts "[!] This causes a new process to execute and is difficult to use safely, Specify the application path in the first argument, NOT as part of the second, or embedded spaces could allow an attacker to force a different program to run".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(atoi|atol)/i) # TODO: Be more specific. The biggest problem involves "first" param NULL, second param with embedded space. Windows.
       puts "[!] Unless checked, the resulting number can exceed the expected range, If source is untrusted, check both minimum and maximum, even if the input had no minus sign (large numbers can roll over into negative number; consider saving to an unsigned value if that is intended)".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
     
    if line.match( 
       /(drand48|erand48|jrand48|lcong48|lrand48|mrand48|nrand48|random|seed48|setstate|srand|strfry|srandom)/i) # Random values. Don't trigger on "initstate", it's too common a term.
       puts "[!] This function is not sufficiently random for security-related functions such as key and nonce creation, use a more secure technique for acquiring random values".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(crypt)/i) 
       puts "[!] Function crypt is a poor one-way hashing algorithm; since it only accepts passwords of 8 characters or less, and only a two-byte salt, it is excessively vulnerable to dictionary attacks given today's faster computing equipment, Use a different algorithm, such as SHA-1, with a larger non-repeating salt".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(EVP_des_ecb|EVP_des_cbc|EVP_des_cfb|EVP_des_ofb|EVP_desx_cbc)/i) # OpenSSL EVP calls to use DES.
       puts "[!] DES only supports a 56-bit keysize, which is too small given today's computers. Use a different patent-free encryption algorithm with a larger keysize, such as 3DES or AES".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(EVP_rc4_40|EVP_rc2_40_cbc|EVP_rc2_64_cbc)/i) # Other OpenSSL EVP calls to use small keys.
       puts "[!] These keysizes are too small given today's computers. Use a different patent-free encryption algorithm with a larger keysize, such as 3DES or AES".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(chroot)/i)
       puts "[!] chroot can be very helpful, but is hard to use correctly. Make sure the program immediately chdir(\"/\"), closes file descriptors, and drops root privileges, and that all necessary files (and no more!) are in the new root".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(getenv|curl_getenv)/i)
       puts "[!] Environment variables are untrustable input if they can be set by an attacker. They can have any content and length, and the same variable can be set more than once. Check environment variables carefully before using them".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(g_get_home_dir)/i)
       puts "[!] This function is synonymous with getenv(\HOME\) it returns untrustable input if the environment can be set by an attacker.  It can have any content and length, " <<
            "and the same variable can be set more than once. Check environment variables carefully before using them".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(g_get_tmp_dir)/i)
       puts "[!] This function is synonymous with 'getenv(\"TMP\")'; it returns untrustable input if the environment can be" <<
            "set by an attacker.  It can have any content and length, and the same variable can be set more than once" <<
            "Check environment variables carefully before using them".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    # These are Windows-unique:
    # TODO: Should have lower risk if the program checks return value.
    if line.match( 
       /(RpcImpersonateClient|ImpersonateLoggedOnUser|CoImpersonateClient|ImpersonateNamedPipeClient|ImpersonateDdeClientWindow|ImpersonateSecurityContext|SetThreadToken)/i)
       puts "[!] If this call fails, the program could fail to drop heightened privileges" <<
            "Make sure the return value is checked, and do not continue if a failure is reported".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
     # These are Windows-unique:
     # TODO: Should have lower risk if the program checks return value.
    if line.match( 
       /(InitializeCriticalSection)/i)
       puts "[!] Exceptions can be thrown in low-memory situations, Use InitializeCriticalSectionAndSpinCount instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(EnterCriticalSection)/i)
       puts "[!] On some versions of Windows, exceptions can be thrown in low-memory situations, Use InitializeCriticalSectionAndSpinCount instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(LoadLibrary|LoadLibraryEx)/i)
       puts "[!] Ensure that the full path to the library is specified, or current directory may be used, Use registry entry or GetWindowsDirectory to find library path, if you aren't already.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(LoadLibrary|LoadLibraryEx)/i)
       puts "[!] Ensure that the full path to the library is specified, or current directory may be used, Use registry entry or GetWindowsDirectory to find library path, if you aren't already.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(SetSecurityDescriptorDacl)/i)
       puts "[!] Never create NULL ACLs; an attacker can set it to Everyone (Deny All Access), which would even forbid administrator access.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(AddAccessAllowedAce)/i)
       puts "[!] This doesn't set the inheritance bits in the access control entry (ACE) header, Make sure that you set inheritance by hand if you wish it to inherit.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(getlogin)/i)
       puts "[!] It's often easy to fool getlogin.  Sometimes it does not work at all, because some program messed up the utmp file.  Often, it gives only the first 8 characters of the login name. The user currently logged in on the controlling tty of our program need not be the user who started it.  Avoid getlogin() for security-related purposes, Use getpwuid(geteuid()) and extract the desired information instead.".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(cuserid)/i)
       puts "[!] Exactly what cuserid() does is poorly defined (e.g., some systems use the effective uid, like Linux, while others like System V use the real uid). Thus, you can't trust what it does. It's certainly not portable (The cuserid function was included in the 1988 version of POSIX, but removed from the 1990 version).  Also, if passed a non-null parameter, there's a risk of a buffer overflow if the passed-in buffer is not at least L_cuserid characters long, Use getpwuid(geteuid()) and extract the desired information instead".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(getpw)/i)
       puts "[!] This function is dangerous; it may overflow the provided buffer. It extracts data from a 'protected' area, but most systems have many commands to let users modify the protected area, and it's not always clear what their limits are. Best to avoid using this function altogether, Use getpwuid() instead".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(getpass)/i)
       puts "[!] This function is obsolete and not portable. It was in SUSv2 but removed by POSIX.2.  What it does exactly varies considerably between systems, particularly in where its prompt is displayed and where it gets its data (e.g., /dev/tty, stdin, stderr, etc.). Make the specific calls to do exactly what you want.  If you continue to use it, or write your own, be sure to zero the password as soon as possible to avoid leaving the cleartext password visible in the process' address space".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(gsignal|ssignal)/i)
       puts "[!] These functions are considered obsolete on most systems, and very non-poertable (Linux-based systems handle them radically different, basically if gsignal/ssignal were the same as raise/signal respectively, while System V considers them a separate set and obsolete), Switch to raise/signal, or some other signalling approach".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(memalign)/i)
       puts "[!] On some systems (though not Linux-based systems) an attempt to free() results from memalign() may fail. This may, on a few systems, be exploitable.  Also note that memalign() may not check that the boundary parameter is correct. Use posix_memalign instead (defined in POSIX's 1003.1d).  Don't switch to valloc(); it is marked as obsolete in BSD 4.3, as legacy in SUSv2, and is no longer defined in SUSv3.  In some cases, malloc()'s alignment may be sufficient".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(ulimit)/i)
       puts "[!] This C routine is considered obsolete (as opposed to the shell command by the same name, which is NOT obsolete). Use getrlimit(2), setrlimit(2), and sysconf(3) instead".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(usleep)/i)
       puts "[!] This C routine is considered obsolete (as opposed to the shell command by the same name).   The interaction of this function with SIGALRM and other timer functions such as sleep(), alarm(), setitimer(), and nanosleep() is unspecified. Use nanosleep(2) or setitimer(2) instead".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
      
    if line.match( 
       /(recv|recvfrom|recvmsg|fread|readv)/i)
       puts "Function accepts input from outside program. Make sure input data is filtered, especially if an attacker could manipulate it".foreground(:yellow).bright
       print "#{filename}:"
       print $. # shows the line number of the file being analyzed.
       print ": "
       puts "#{line}".foreground(:white).bright
    end
  end
      
# TODO: This must be identical to the above in order for the scoring to be 100% accurate!
  dfuncs = %w{ strcpy lstrcpy wcscpy _tcscpy _mbscpy memcpy CopyMemory bcopy strcat lstrcat wcscat _tcscat _mbscat strncpy lstrcpyn wcsncpy _tcsncpy _mbsnbcpy 
               strncat lstrcatn wcsncat _tcsncat _mbsnbcat strccpy strcadd char TCHAR wchar_t gets _getts sprintf vsprintf swprintf vswprintf _stprintf _vstprintf
               printf vprintf vwprintf vfwprintf _vtprintf fprintf vfprintf _ftprintf _vftprintf syslog snprintf vsnprintf _snprintf _sntprintf _vsntprintf
	       scanf vscanf wscanf _tscanf fscanf sscanf vsscanf vfscanf _ftscanf strlen wcslen _tcslen _mbslen MultiByteToWideChar streadd strecpy strtrns
	       realpath getopt getopt_long getpass getwd getchar fgetc getc read _gettc access chown chgrp chmod vfork readlink tmpfile tmpnam tempnam
	       mktemp mkstemp fopen open umask GetTempFileName execl execlp execle execv execvp system popen WinExec ShellExecute CreateProcessAsUser 
	       CreateProcessWithLogon CreateProcess atoi|atol drand48 erand48 jrand48 lcong48 lrand48 mrand48 nrand48 random seed48 setstate srand strfry srandom
	       crypt EVP_des_ecb EVP_des_cbc EVP_des_cfb EVP_des_ofb EVP_desx_cbc EVP_rc4_40 EVP_rc2_40_cbc EVP_rc2_64_cbc chroot getenv curl_getenv g_get_home_dir
	       g_get_tmp_dir RpcImpersonateClient ImpersonateLoggedOnUser CoImpersonateClient ImpersonateNamedPipeClient ImpersonateDdeClientWindow ImpersonateSecurityContext
               SetThreadToken InitializeCriticalSection EnterCriticalSection LoadLibrary LoadLibraryEx SetSecurityDescriptorDacl AddAccessAllowedAce getlogin cuserid getpw getpass
	       gsignal ssignal memalign ulimit usleep recv recvfrom recvmsg fread readv
             }

# Make a list of words in the text that aren't dangerous,
# count them, and work out the percentage against all words
all_words       = text.scan(/\w+/)
good_words      = all_words.select{ |word| !dfuncs.include?(word) }
good_percentage = ((good_words.length.to_f / all_words.length.to_f) * 100).to_i

# Echo final results to user :::
puts "Step 3/3:".foreground(:white).underline.bright << " Ready to display the overall percentage score for #{filename}.".foreground(:cyan)
puts "Score guidelines are: <= (less than) 98% questionable code, >= (greater than) 99% secure code.".foreground(:cyan)

if good_percentage <= 99
  print "\nFinal security score for \"#{filename}\" is " << "#{good_percentage}%".foreground(:red).blink << " <-- Your code sux!\n".upcase
  elsif good_percentage >=100
  print "\nFinal security score for \"#{filename}\" is " << "#{good_percentage}%".foreground(:red).blink << " <-- Good job on passing the test! Either your code is secure or it does not contain any of the 160 dangerous functions above that this test scores against. Either way, manually checking your code is recommended.\n".upcase
end

puts "-- End of analysis\n\n"
puts "[!] This is merely a quick static test against 160 dangerous functions. I recommend you follow a secure SDLC before deploying your code.".foreground(:yellow).bright
puts "[!] Not every hit found is necessarily a security vulnerability. There may also be other uncovered security vulnerabilities; review your code!".foreground(:yellow).bright
