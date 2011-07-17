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
import re
import time
import ConfigParser
import sre_constants


CONFIG_FILE = '/etc/mpsr.conf'

def deny_access(url):
    return 'http://192.168.2.1/access_denied.html'

def clamav(url):
    process = subprocess.Popen('/usr/local/bin/squidclamav -c /usr/local/etc/squidclamav.conf', shell=False,
            stdout=subprocess.PIPE,stdin=subprocess.PIPE)
    process.communicate(url)
    result = process.stdout.read()
    print ("clamav result", result)
    return result

def redirect(conf, rule):
    '''
    Redirects to a given url
    '''
    if not conf.has_option(rule, 'url'):
        return
    newurl = conf.get(rule, 'url')
    if not newurl:
        return
    return newurl

METHODS = {
        'redirect': redirect,
        }

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
        ('boosters','http.?://.*download-boosters.*', deny_access),
        ('search.bearshare','http.?://search.bearshare\..{2,3}', lambda url: 'http://www.la-uno.com/html/index.php'),
        ('bearshare','http.?://.*bearshare\..{2,3}', deny_access),
        #('Everyting Else', '.*', clamav),
        ('Everyting Else', '.*', lambda url: url),
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
            #print "procesando ", rule[0]
            result = func(line)
            return True, result
        except Exception, e:
            #print e
            pass
    return False, result 

def _handle_config_rules(line, conf):
    for section in conf.sections():
        #Useless rule
        if not conf.has_option(section, 'method'): 
            continue
        method =  conf.get(section, 'method')
        methodobj = METHODS.get(method, None)
        #Useless rule
        if not callable(methodobj): 
            continue
        #Useless rule
        if not conf.has_option(section, 'match'): 
            continue
        match = conf.get(section, 'match')
        #Useless rule
        if not match: 
            continue
        try:
            pattern = re.compile(match, re.I)
        except sre_constants.error, e:
            #An invalid regular expression just happened.
            continue
        matches =  []
        c = re.findall(pattern, line)
        # Rule does not apply
        if not c: 
            continue
        try:
            return methodobj(conf, section)
        except:
            continue

def run():
    while 1:
        #Get the url
        line = sys.stdin.readline().strip()
        if not line:
            #print 1
            time.sleep(0.1)
            continue
        #Open the configuration file.
        conf = ConfigParser.ConfigParser()
        if not conf.read(CONFIG_FILE):
            #Apply default rules.
            for rule in RULES:
                result  = handle_rule(rule, line)
                if result[0]:
                    sys.stdout.write(result[1]+"\n")
                    sys.stdout.flush()
                    break
        try:
            result = _handle_config_rules(line, conf)
            if not result:
                result = line
        except:
            result = line
        sys.stdout.write(result + "\n")
        sys.stdout.flush()


if __name__ == '__main__':
    run()
