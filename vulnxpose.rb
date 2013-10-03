#!/usr/bin/env ruby
require 'rainbow'

=begin
#   :::$Id: vulnxpose.rb 6191 20nano $
#   :::Source k0de Analyzer koded by Nanotechz9l
#   :::zet Xterm to 102x24 for better reZUltSss./|
#   :::$Revision: 0.1 $
=end

def b()
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
text=''

# File implements a readlines method that reads an entire file into an array line by line 
# You can use this both to count the lines and join them all into a single string
lines 		= File.readlines(ARGV[0]) # or I could use ARGV.first which is the same thing :)
line_count 	= lines.size
text 		= lines.join
b()

if not ARGV[0]
 print "\nMISSING input file!".foreground(:red).bright
 print "\nUsage: #{$0} vulnfile.c\n\n".foreground(:white).bright
 exit(0)
 b()
end

# User greet!
puts "\n\tVULNXPOSE v0.1 written by ".foreground(:red) << "Rick <@nanotechz9l> Flores".foreground(:white)
puts "\tI scan .c source files for known dangerous/banned functions, & calculate an overall security score.".foreground(:red)

# Echo the number of lines in source file
results = []
words = 0
chars = 0
minline = 0
maxline = 0

# Analyze file information stolen from: http://redneckprogrammer.blogspot.com/2007/09/word-character-line-counter-ruby-script.html
filename = ARGV[0]
File.new(filename, "r").each { |line| results << line }

puts "\nStep 1/3:".foreground(:white).underline.bright << " Gathering basic file information from #{filename}... (need to know what im dealing with)".foreground(:cyan)
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
puts " -> #{maxline} characters longest line length."

# Start analyzing source file for security vulns
File.open(ARGV[0]) do |f|
  f.each_line do |line|
    if line =~ /sprintf/ # need to add regex support <-member to update dfuns aswell!!
      puts "\nStep 2/3:".foreground(:white).underline.bright << " Starting security analysis on #{filename}...".foreground(:cyan)
      puts "The following potentially dangerous methods were found:::".foreground(:red)
      puts "sprintf: #{line}".foreground(:white)
    end
  end
end

# Dangerous functions // expiremental!
dfuncs = %w{sprintf}

# Make a list of words in the text that aren't dangerous,
# count them, and work out the percentage against all words
all_words = text.scan(/\w+/)
good_words = all_words.select{ |word| !dfuncs.include?(word) }
good_percentage = ((good_words.length.to_f / all_words.length.to_f) * 100).to_i

#Echo final results to user :::
puts "Step 3/3:".foreground(:white).underline.bright << " Ready to display the overall percentage score for #{filename}.".foreground(:cyan)
puts "Score guidelines are: <= (less than) 97% horrible code, >= (greater than) 97% secure code.".foreground(:cyan)
puts "\nFinal security score for #{filename} is" << " #{good_percentage}%".foreground(:red).blink # this now working as expected.
puts "-- End of analysis\n\n"