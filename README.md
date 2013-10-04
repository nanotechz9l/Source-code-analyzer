
Vulnxpose
==============

Scans C/C++ source code files for known vulnerabilities including buffer overflows, race conditions, weak crypto, chroot jail configs ... & more).

Written by Rick Flores @nanotechz9l

![Screenshot](http://img10.imageshack.us/img10/7636/fpg5.png)

## Pre Reqs

You MUST install the rainbow gem for the pretty colorized output seen above:

	gem install rainbow
	
## Usage
	./vulnxpose.rb vuln-test-file.c
	
## Features

 ![Screenshot](http://img600.imageshack.us/img600/1108/to5y.png)

* Scans C/C++ files for known vulnerabilities (buffer overflows, race conditions, weak crypto, chroot jail config... & more).
* Provides a calculated score based on dangerous functions found in the source code.
* Provides vulnerability information, and code recommendations. 

## Requirements
* Tested on ruby version/s:
	* ruby 2.0.0p0 (2013-02-24 revision 39474)
	* ruby 1.9.3

## History
* 10/04/2013 - Updated dfuncs to include all flawfinders 160 dangerous functions
* 10/03/2013 - Added line number output.
* 10/03/2013 - Added all 160 flawfinder dangerous functions.
* 10/03/2013 - Added simple regex search to scan multiple functions vs one.
* 10/02/2013 - Wrote the quick PoC.

## BUG LIST:
* [X] SQUASHED - Improve the regex search (include all 160 flawfinder functions), and test
* [X] SQUASHED - Add vulnerability information, and recommendations.
* [X] SQUASHED - Improve the regex search findings output
* [X] SQUASHED - Add line numbers for function in question to vulnerability information, and recommendations!
* [X] SQUASHED - Update dfuncs to include the newly added c_rules 160 dangerous functions (makes scoring 100% accurate)!
* Fix an error when no ARGV is given at runtime.

## Credits
* Rick Flores (@nanotechz9l) -- 0xnanoquetz9l[--at--]gmail.com

## License
This code is free software; you can redistribute it and/or modify it under the
terms of the new BSD License.
