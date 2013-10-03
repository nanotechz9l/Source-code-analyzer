#!/usr/bin/env ruby

require 'rainbow';require 'rubygems'

=begin
#   :::$Id: analyZer.rb 6191 2011-04-05 0126hrs nano $
#   :::Source k0de Analyzer koded by Nanotechz9l
#   :::zet Xterm to 102x24 for better reZUltSss./|
#   :::$Revision: 1.0.0.1 $
         _   _                   _____            _                      
        | \ | |                 |  ___|          | |                     
        |  \| | __ _ _ __   ___ | |__ _ __   __ _| |_ __   ___  ___ _ __ 
        | . ` |/ _` | '_ \ / _ \|  __| '_ \ / _` | | '_ \ / _ \/ _ \ '__|
        | |\  | (_| | | | | (_) | |__| | | | (_| |_| | | |  __/  __/ |   
        \_| \_/\__,_|_| |_|\___/\____/_| |_|\__, (_)_| |_|\___|\___|_|   
                                             __/ |                       
                                            |___/     
  [~] 0x0, Load file containing the text or       document you want to analyze.
  [~] 0x1, Put the text into a string and measure its length to get a character count.
  [~] 0x2, Remove whitespace to get the character count excluding spaces.
  [~] 0x3, Split out all the whitespace to find out how many words there are.
  [~] 0x4, Split on full stops to find out how many sentences there are.
  [~] 0x5, Split on double newlines to find out how many paragraphs there are.
  [~] 0x6, Perform calculations to work out the averages.

  Copyright (C) 2011  Rick Flores AKA Nanotechz9l | nanotechz9l<v>gmail

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
=end

# Kreate the variable text
text=''

# File implements a readlines method that reads an entire file into an array line by line 
# You can use this both to count the lines and join them all into a single string
lines 		= File.readlines(ARGV[0]) # or I could use ARGV.first which is the same thing :)
line_count 	= lines.size
text 		= lines.join

# User greet!
#puts "TOP SECRET | Majic Eyes 0NLY".foreground(:red).bright.blink

# Echo the number of x(lines)
puts "Analyzing #{line_count} lines from #{ARGV[0]} file.".foreground(:white)

File.open(ARGV[0]) do |f|
  f.each_line do |line|
    if line =~ /sprintf/
      puts "\nThe following potentially dangerous methods were found:::".foreground(:red)
      puts "Found sprintf: #{line}".foreground(:white)
    end
  end
end

# Dangerous functions
dfuncs = %w{sprintf strcpy}

# Make a list of words from the input file that aren't dangerous functions,
# count them, and work out the percentage against all words.
all_words 	= text.scan(/\w+/)
good_words 	= all_words.select{ |word| !dfuncs.include?(word) }
good_percentage = ((good_words.length.to_f / all_words.length.to_f) * 100).to_i

#Echo final results to user :::
puts "#{good_percentage}% of functions are not dangerous"
#puts "Summary:\n" + ideal_sentences.join(". ")
#puts "#{dfuncs}"
puts "-- End of analysis\n\n"