#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of the Markuz Python Squid Redirector project
#
# Copyright (c) 2011 Marco Antonio Islas Cruz
#
# Markuz Python Squid Redirector is free software; 
# you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Markuz Python Squid Redirector is distributed in the hope that 
# it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#
# @author    Marco Antonio Islas Cruz <markuz@islascruz.org>
# @copyright 2011 Marco Antonio Islas Cruz
# @license   http://www.gnu.org/licenses/gpl.txt


import sys
import subprocess

def deny_access(url):
    return 'http://192.168.2.1/access_denied.html'

def clamav(url):
    process = subprocess.Popen('/usr/local/bin/squidclamav', shell=True,
            stdout=subprocess.PIPE)
    process.communicate(url)
    return process.stdout.read()

#
# RULES is tuple of tuples.
# Every tuple is a new rule, the first element is the name of the rule 
# the second is the rule to be matched through regular expression.
# the second is the function that modifies the line.
#
# Every  modifier function will be called with the url as the 
# first argument, and should return (never print) a string.
#
# First rule matched will be used.

RULES = (
        ('Softonic Downloader','.*SoftonicDownloader.*', deny_access),
        ('aTube','.*aTube.*', deny_access),
        ('Conduit','http.?://.*conduit.com.*', deny_access),
        ('facemods','http.?://.*facemoods.com.*', deny_access),
        ('Everyting Else', '.*', lambda url: call_subprocess(url, )),
        )


def handle_rule(rule, line):
    '''
    Process a single rule. and returns empty if nothing has to be done, or 
    the result of the func defined in the rule.

    @param rule: tuple with name, regex and func to be called.
    @param url: string url.
    '''
    result = ''
    pattern = re.compile(rule[1], re.I)
    matches =  []
    c = re.findall(pattern, line)
    if c:
        func = rule[2]
        #If function is defective then do nothing...
        try:
            result = func(line)
            break
        except:
            pass
    return 

while 1:
    #Get the url
    line = sys.stdin.readline().strip()
    for rule in RULES:
        result  = handle_rule(rule, line)
        sys.stdout.write(result+"\n")
        sys.stdout.flush()


