
Vulnxpose
==============

This script automatically scans C/C++ source files for banned/dangerous functions.

Written by Rick Flores @nanotechz9l

![Screenshot](http://img10.imageshack.us/img10/7636/fpg5.png)

## Pre Reqs

You MUST install the rainbow gem for the pretty colorized output seen above:

	gem install rainbow
	
## Usage
	./vulnxpose.rb vuln-test-file.c
	
## Features

 ![Screenshot](http://img600.imageshack.us/img600/1108/to5y.png)

* Scans C/C++ files for known vulnerabilities.
* Provides a calculated score based on dangerous functions found in the source code.
* Provides vulnerability information, and code recommendations. 

## Requirements
* Tested on ruby version/s:
	* ruby 2.0.0p0 (2013-02-24 revision 39474)
	* ruby 1.9.3

## History
* 10/02/2013 - Wrote the quick PoC.
* 10/03/2013 - Added simple regex search to scan multiple functions vs one.

## To Do
* Improve the regex search (include all 160 functions), and test
* Improve the regex search findings output
* Add vulnerability information, and recommendations.
* Add line numbers to vulnerability information, and recommendations!
* Update dfuncs to include the newly added c_rules 160 dangerous functions!
* Fix an error when no ARGV is given at runtime.

## Credits
* Rick Flores (@nanotechz9l) -- 0xnanoquetz9l[--at--]gmail.com

## License
This code is free software; you can redistribute it and/or modify it under the
terms of the new BSD License.
