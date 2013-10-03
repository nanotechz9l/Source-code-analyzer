#!/usr/bin/env ruby
require 'rainbow'

=begin
#   :::$Id: analyZer.rb 6191 2011-04-05 0126hrs nano $
#   :::Source k0de Analyzer koded by Nanotechz9l
#   :::zet Xterm to 102x24 for better reZUltSss./|
#   :::$Revision: 1.0.0.1 $
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
"""
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
#puts "TOP SECRET | Majic Eyes 0NLY".foreground(:red).bright.blink

# Echo the number of x(lines)
puts "Analyzing #{line_count} lines from #{ARGV[0]} file.".foreground(:white)

File.open(ARGV[0]) do |f|
  f.each_line do |line|
    if line =~ /sprintf/ # need to add regex support <-member to update dfuns aswell!!
      puts "\nThe following potentially dangerous methods were found:::".foreground(:red)
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
puts "#{good_percentage}% of functions are not dangerous" # this does not seem to be 100% accurate!
puts "-- End of analysis\n\n"