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

  Copyright (C) 2011  Rick Flores AKA Nanoquetz9l | nanobotc0de<@>gmail

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
lines = File.readlines(ARGV[0]) # or I could use ARGV.first which is the same thing :)
line_count = lines.size
text = lines.join

# User greet!
puts "TOP SECRET | Majic Eyes 0NLY".foreground(:red).bright.blink
puts "Ruby finished its disassembly & autopsy of the file :::".foreground(:red)
puts "There are a total of the following dangerous methods :::".foreground(:red)

# Echo the number of x(lines)
puts "#{line_count} lines".foreground(:white)

# Counting characters in a file
total_characters = text.length
puts "#{total_characters} characters".foreground(:white)

# Use gsub method to eliminate whitespace
total_characters_nospaces = text.gsub(/\s+/, '').length
puts "#{total_characters_nospaces} characters excluding (whitespaces)".foreground(:white)

# Counting words with the split method
word_count = text.split.length
puts "#{word_count} words".foreground(:white)

# Counting sentences & paragraphs with split method & a regular expression
paragraph_count = text.split(/\n\n/).length
puts "#{paragraph_count} paragraphs".foreground(:white)

# Sentence count
sentence_count = text.split(/\.|\?|!/).length
puts "#{sentence_count} sentences".foreground(:white)

# Calculating sentences per paragrpah
puts "#{sentence_count / paragraph_count} sentences per paragraph".foreground(:white)

# Calculating words per paragraph
puts "#{word_count / sentence_count} words per sentence (average)".foreground(:white)

# Stop w0rds
stopwords = %w{the a by on for are with just but and to the my I has some in}

# Make a list of words in the text that aren't stop words,
# count them, and work out the percentage of non-stop words
# against all words
all_words = text.scan(/\w+/)
good_words = all_words.select{ |word| !stopwords.include?(word) }
good_percentage = ((good_words.length.to_f / all_words.length.to_f) * 100).to_i

# Summarize the text by cherry picking some choice sentences
sentences = text.gsub(/\s+/, ' ').strip.split(/\.|\?|!/)
sentences_sorted = sentences.sort_by { |sentence| sentence.length }
one_third = sentences_sorted.length / 3
ideal_sentences = sentences_sorted.slice(one_third, one_third + 1)
ideal_sentences = ideal_sentences.select { |sentence| sentence =~ /is|are/ }

#Echo final results to user :::
puts "#{good_percentage}% of words are non-fluff words"
puts "Summary:\n\n" + ideal_sentences.join(". ")
puts "-- End of analysis"