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
import os
import subprocess
import re
import time
import ConfigParser
import logging
import logging.handlers
import MySQLdb
import threading




conf = ConfigParser.ConfigParser()
def load_defaults():
    """Load configuration settings."""
    defaults = {
        "mysql": {
            "host": "localhost",
            "port": "3306",
            "user": "",
            "password": "",
            "database" : "mpsr"
        },
        "logging":{
            "path":"/tmp/"
            }
    }
    # Load in default values.
    for section, values in defaults.iteritems():
        conf.add_section(section)
        for option, value in values.iteritems():
            conf.set(section, option, value)
    if os.path.exists("/etc/mpsr.conf"):
        # Overwrite with local values.
        conf.read("/etc/mpsr.conf")
    else:
        with open ("/etc/mpsr.conf","w+") as f:
            conf.write(f)
load_defaults()

logging_path = conf.get("logging","path")

def connect():
    #Connect to database.
    db = MySQLdb.connect(host = conf.get("mysql","host"), 
                        port=int(conf.get("mysql","port")),
                        user = conf.get("mysql","user"),
                        passwd = conf.get("mysql","password"),
                        db = conf.get("mysql", "database"))
    cursor = db.cursor()
    return db

class LoggerManager:
    def __init__(self):
        self.loggers = {}
        formatter = logging.Formatter('%(asctime)s:%(levelname)-8s:%(name)-10s:%(lineno)4s: %(message)-80s')
        level = 'DEBUG'
        nlevel = getattr(logging, level, None)
        self.LOGGING_MODE = nlevel
        logfile = os.path.join(logging_path, 'mpsr.log')
        errorfile = os.path.join(logging_path, 'mpsr_errors.log')
        self.LOGGING_HANDLER = logging.handlers.RotatingFileHandler(logfile,'a')
        self.ERROR_HANDLER = logging.handlers.RotatingFileHandler(errorfile,'a')

        self.LOGGING_HANDLER.setFormatter(formatter)
        self.LOGGING_HANDLER.setLevel(self.LOGGING_MODE)
        self.ERROR_HANDLER.setFormatter(formatter)
        self.ERROR_HANDLER.setLevel(self.LOGGING_MODE)
    
    def getLogger(self, loggername):
        if not self.loggers.has_key(loggername):
            logger = Logger(loggername, self.LOGGING_HANDLER, 
                        self.ERROR_HANDLER, self.LOGGING_MODE)
            self.loggers[loggername] = logger
        return self.loggers[loggername]

class Logger:
    '''
    Implements the christine logging facility.
    '''
    def __init__(self, loggername, logging_handler, error_handler, logging_mode, 
                type='event'):
        '''
        Constructor, construye una clase de logger.
        
        @param loggername: Nombre que el logger tendra.
        @param type: Tipo de logger. Los valores disponibles son : event y error
                    por defecto apunta a event. En caso de utilizarse otro
                    que no sea event o error se apuntara a event.
        ''' 
        # Create two logger,one for info, debug and warnings and another for  
        # errors, exceptions and criticals
        self.__Logger = logging.getLogger(loggername)
        self.__ErrorLogger = logging.getLogger('Error'+ loggername)
        
        #Establecemos las propiedades de los loggers.
        self.__Logger.setLevel(logging_mode)
        self.__Logger.addHandler(logging_handler)
        
        self.__ErrorLogger.setLevel(logging_mode)
        self.__ErrorLogger.addHandler(error_handler)

        self.info = self.__Logger.info
        self.debug = self.__Logger.debug
        self.warning = self.__Logger.warning
        
        self.critical = self.__ErrorLogger.critical
        self.error = self.__ErrorLogger.error
        self.exception = self.__ErrorLogger.exception
    


logger = LoggerManager().getLogger("mpsr")


def doreload(conf):
    '''Returns true if we need to reload the configuration file
    '''
    if not conf:
        return True
    if os.path.exists("/etc/mpsr_noreload"):
        return False

def deny_access(url):
    return 'http://192.168.2.1/access_denied.html'

def clamav(url):
    process = subprocess.Popen('/usr/local/bin/squidclamav -c /usr/local/etc/squidclamav.conf', shell=False,
            stdout=subprocess.PIPE,stdin=subprocess.PIPE)
    process.communicate(url)
    result = process.stdout.read()
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

####RULES = (
####        ('Softonic Downloader','.*SoftonicDownloader.*', deny_access),
####        ('aTube','.*aTube.*', deny_access),
####        ('Conduit','http.?://.*conduit.com.*', deny_access),
####        ('facemods','http.?://.*facemoods.com.*', deny_access),
####        ('boosters','http.?://.*download-boosters.*', deny_access),
####        ('search.bearshare','http.?://search.bearshare\..{2,3}', lambda url: 'http://www.la-uno.com/html/index.php'),
####        ('bearshare','http.?://.*bearshare\..{2,3}', deny_access),
####        #('Everyting Else', '.*', clamav),
####        ('Everyting Else', '.*', lambda url: url),
####        )


def handle_rule(rule, line):
    '''
    Process a single rule. and returns empty if nothing has to be done, or 
    the result of the func defined in the rule.

    @param rule: tuple with name, regex and func to be called.
    @param url: string url.
    '''
    result = ''
    pattern = re.compile(rule[1], re.I)
    c = re.findall(pattern, line)
    if c:
        func = rule[2]
        #If function is defective then do nothing...
        try:
            #print "procesando ", rule[0]
            result = func(line)
            return True, result
        except Exception:
            #print e
            pass
    return False, result 

def _handle_config_rules(line, conf):
    #logger.debug("conf: %r"%conf)
    #logger.debug("conf.sections(): %r"%conf.sections())
    db = connect()
    cursor = db.cursor()
    query = ("SELECT method, url FROM sites WHERE enabled = 1 "
        " AND (SELECT %s REGEXP `match`) = 1")
    cursor.execute(query, (line, ))
    sites = cursor.fetchall()
    cursor.close()
    db.close()
    if not sites:
        return line
    working_match = sites[0]
    for working_match in sites:
        return working_match[1]           
    return line

def process_line(line, conf, latest_update, stdout):
    if not line:
        time.sleep(0.1)
        return conf, latest_update
    logger.debug("line: %r"%line)
    split = [k.strip() for k in line.split()]
    CHANNEL, URL,IP, dash, METHOD,  = split[:5]
    keypair = line.split(" ",5)[-1]
    pc = IP
    if len(split) > 1:
        if split[1].startswith("http"):
            line = split[1]
            try:
                pc = split[2].split("/",1)[0]
            except:
                pass
        else:
            line = split[3]    
            try:
                pc = split[3].split("/",1)[0]
            except:
                pass

    db = connect()
    cursor = db.cursor()
    # Get the ipaddrs to skip.
    cursor.execute("SELECT ipaddr FROM users")
    ips = cursor.fetchall()
    cursor.close()
    db.close()
    if pc in ips:
        logger.info("Skipping because %s is in the whitelist"%pc)
        logger.info ("%s - %s => %s"%(pc, line, line))
        stdout.write("%s OK"%CHANNEL)
        stdout.flush()
        return conf, latest_update
    try:
        result = _handle_config_rules(URL, conf)
        if result == URL:
            #result = "%s OK"%CHANNEL
            #result = "%s OK url=%s status=200 %s %s %s\n"%(CHANNEL, result, IP, METHOD, keypair)
            result = "%s %s\n"%(CHANNEL, result)
        else:
            result = "%s %s\n"%(CHANNEL, result)
    except Exception, e:
        logger.error("There is an exception, %s"%repr(e))
        result = line
    logger.info ("%d - %s - %s => %s"%(os.getpid(), pc, URL, result))
    stdout.write(result)
    stdout.flush()
    return conf, latest_update

def run():
    conf = None
    latest_update = time.time()
    stdout = sys.stdout
    starttime = time.time()
    while 1:
        #Get the url
        line = sys.stdin.readline().strip()
        if not line:
            time.sleep(0.01)
            if time.time() - starttime > 60:
                logger.info("Exit the program because inactivity")
                sys.exit()
            continue
        try:
            args = (line, conf, latest_update,stdout)
            thr = threading.Thread(target = process_line, args = args)
            thr.start()
            time.sleep(0.01)
            starttime = time.time()
        except Exception, e:
            logger.error(e)
            logger.info(e)
            sys.exit(-1)

if __name__ == '__main__':
    run()
