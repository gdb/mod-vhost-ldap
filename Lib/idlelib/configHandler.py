"""
Provides access to stored idle configuration information.
"""
# Throughout this module there is an emphasis on returning useable defaults
# when a problem occurs in returning a requested configuration value back to
# idle. This is to allow idle to continue to function in spite of errors in
# the retrieval of config information. When a default is returned instead of
# a requested config value, a message is printed to stderr to aid in 
# configuration problem notification and resolution. 

import os
import sys
from ConfigParser import ConfigParser, NoOptionError, NoSectionError

class IdleConfParser(ConfigParser):
    """
    A ConfigParser specialised for idle configuration file handling
    """
    def __init__(self, cfgFile, cfgDefaults=None):
        """
        cfgFile - string, fully specified configuration file name
        """
        self.file=cfgFile
        ConfigParser.__init__(self,defaults=cfgDefaults)
    
    def Get(self, section, option, type=None):
        """
        Get an option value for given section/option or return default.
        If type is specified, return as type.
        """
        if type=='bool': 
            getVal=self.getboolean
        elif type=='int': 
            getVal=self.getint
        else: 
            getVal=self.get
        if self.has_option(section,option):
            #return getVal(section, option, raw, vars)
            return getVal(section, option)

    def GetOptionList(self,section):
        """
        Get an option list for given section
        """
        if self.has_section:
            return self.options(section)
        else:  #return a default value
            return []

    def Load(self):
        """ 
        Load the configuration file from disk 
        """
        self.read(self.file)
        
class IdleUserConfParser(IdleConfParser):
    """
    IdleConfigParser specialised for user configuration handling
    """
    def Save(self):
        """
        write loaded user configuration file back to disk
        """
        # this is a user config, it can be written to disk
        self.write()

class IdleConf:
    """
    holds config parsers for all idle config files:
    default config files
        (idle install dir)/config-main.def
        (idle install dir)/config-extensions.def
        (idle install dir)/config-highlight.def
        (idle install dir)/config-keys.def
    user config  files
        (user home dir)/.idlerc/config-main.cfg
        (user home dir)/.idlerc/config-extensions.cfg
        (user home dir)/.idlerc/config-highlight.cfg
        (user home dir)/.idlerc/config-keys.cfg
    """
    def __init__(self):
        self.defaultCfg={}
        self.userCfg={}
        self.cfg={}
        self.CreateConfigHandlers()
        self.LoadCfgFiles()
        #self.LoadCfg()
            
    def CreateConfigHandlers(self):
        """
        set up a dictionary of config parsers for default and user 
        configurations respectively
        """
        #build idle install path
        if __name__ != '__main__': # we were imported
            idledir=os.path.dirname(__file__)
        else: # we were exec'ed (for testing only)
            idledir=os.path.abspath(sys.path[0])
        #print idledir
        try: #build user home path
            userdir = os.environ['HOME'] #real home directory
        except KeyError:
            userdir = os.getcwd() #hack for os'es without real homedirs
        userdir=os.path.join(userdir,'.idlerc')
        #print userdir
        if not os.path.exists(userdir):
            os.mkdir(userdir)
        configTypes=('main','extensions','highlight','keys')
        defCfgFiles={}
        usrCfgFiles={}
        for cfgType in configTypes: #build config file names
            defCfgFiles[cfgType]=os.path.join(idledir,'config-'+cfgType+'.def')                    
            usrCfgFiles[cfgType]=os.path.join(userdir,'config-'+cfgType+'.cfg')                    
        for cfgType in configTypes: #create config parsers
            self.defaultCfg[cfgType]=IdleConfParser(defCfgFiles[cfgType])
            self.userCfg[cfgType]=IdleUserConfParser(usrCfgFiles[cfgType])
    
    def GetOption(self, configType, section, option, default=None, type=None):
        """
        Get an option value for given config type and given general 
        configuration section/option or return a default. If type is specified,
        return as type. Firstly the user configuration is checked, with a 
        fallback to the default configuration, and a final 'catch all' 
        fallback to a useable passed-in default if the option isn't present in 
        either the user or the default configuration.
        configType must be one of ('main','extensions','highlight','keys')
        If a default is returned a warning is printed to stderr.
        """
        if self.userCfg[configType].has_option(section,option):
            return self.userCfg[configType].Get(section, option, type=type)
        elif self.defaultCfg[configType].has_option(section,option):
            return self.defaultCfg[configType].Get(section, option, type=type)
        else:
            warning=('\n Warning: configHandler.py - IdleConf.GetOption -\n'+
                       ' problem retrieving configration option '+`option`+'\n'+
                       ' from section '+`section`+'.\n'+
                       ' returning default value: '+`default`+'\n')
            sys.stderr.write(warning)
            return default
    
    def GetSectionList(self, configSet, configType):
        """
        Get a list of sections from either the user or default config for 
        the given config type.
        configSet must be either 'user' or 'default' 
        configType must be one of ('main','extensions','highlight','keys')
        """
        if not (configType in ('main','extensions','highlight','keys')):
            raise 'Invalid configType specified'
        if configSet == 'user':
            cfgParser=self.userCfg[configType]
        elif configSet == 'default':
            cfgParser=self.defaultCfg[configType]
        else:
            raise 'Invalid configSet specified'
        return cfgParser.sections()
    
    def GetHighlight(self, theme, element, fgBg=None):
        """
        return individual highlighting theme elements.
        fgBg - string ('fg'or'bg') or None, if None return a dictionary
        containing fg and bg colours (appropriate for passing to Tkinter in, 
        e.g., a tag_config call), otherwise fg or bg colour only as specified. 
        """
        #get some fallback defaults
        defaultFg=self.GetOption('highlight', theme, 'normal' + "-foreground",
            default='#000000')
        defaultBg=self.GetOption('highlight', theme, 'normal' + "-background",
            default='#ffffff')
        #try for requested element colours
        fore = self.GetOption('highlight', theme, element + "-foreground")
        back = None
        if element == 'cursor': #there is no config value for cursor bg
            back = None
        else:    
            back = self.GetOption('highlight', theme, element + "-background")
        #fall back if required
        if not fore: fore=defaultFg
        if not back: back=defaultBg
        highlight={"foreground": fore,"background": back}
        if not fgBg: #return dict of both colours
            return highlight
        else: #return specified colour only
            if fgBg == 'fg':
                return highlight["foreground"]
            if fgBg == 'bg':
                return highlight["background"]
            else:    
                raise 'Invalid fgBg specified'
            

    def GetTheme(self, name=None):
        """
        Gets the requested theme or returns a final fallback theme in case 
        one can't be obtained from either the user or default config files.
        """
        pass
    
    def CurrentTheme(self):
        """
        Returns the name of the currently active theme        
        """
        return self.GetOption('main','Theme','name',default='')
        

    def CurrentKeys(self):
        """
        Returns the name of the currently active theme        
        """
        return self.GetOption('main','Keys','name',default='')
    
    def GetExtensions(self, activeOnly=1):
        """
        Gets a list of all idle extensions declared in the config files.
        activeOnly - boolean, if true only return active (enabled) extensions
        """
        extns=self.RemoveKeyBindNames(
                self.GetSectionList('default','extensions'))
        userExtns=self.RemoveKeyBindNames(
                self.GetSectionList('user','extensions'))
        for extn in userExtns:
            if extn not in extns: #user has added own extension
                extns.append(extn) 
        if activeOnly:
            activeExtns=[]
            for extn in extns:
                if self.GetOption('extensions',extn,'enable',default=1,
                    type='bool'):
                    #the extension is enabled
                    activeExtns.append(extn)
            return activeExtns
        else:
            return extns        

    def RemoveKeyBindNames(self,extnNameList):
        #get rid of keybinding section names
        names=extnNameList
        kbNameIndicies=[]
        for name in names:
            if name.endswith('_bindings') or name.endswith('_cfgBindings'): 
                    kbNameIndicies.append(names.index(name))
        kbNameIndicies.sort()
        kbNameIndicies.reverse()
        for index in kbNameIndicies: #delete each keybinding section name    
            del(names[index])
        return names
        
    def GetExtensionKeys(self,extensionName):
        """
        returns a dictionary of the configurable keybindings for a particular
        extension,as they exist in the dictionary returned by GetCurrentKeySet;
        that is, where previously re-used bindings are disabled.
        """
        keysName=extensionName+'_cfgBindings'
        activeKeys=self.GetCurrentKeySet()
        extKeys={}
        if self.defaultCfg['extensions'].has_section(keysName):
            eventNames=self.defaultCfg['extensions'].GetOptionList(keysName)
            for eventName in eventNames:
                event='<<'+eventName+'>>'
                binding=activeKeys[event]
                extKeys[event]=binding
        return extKeys 
        
    def __GetRawExtensionKeys(self,extensionName):
        """
        returns a dictionary of the configurable keybindings for a particular
        extension, as defined in the configuration files, or an empty dictionary
        if no bindings are found
        """
        keysName=extensionName+'_cfgBindings'
        extKeys={}
        if self.defaultCfg['extensions'].has_section(keysName):
            eventNames=self.defaultCfg['extensions'].GetOptionList(keysName)
            for eventName in eventNames:
                binding=self.GetOption('extensions',keysName,
                        eventName,default='').split()
                event='<<'+eventName+'>>'
                extKeys[event]=binding
        return extKeys 
    
    def GetExtensionBindings(self,extensionName):
        """
        Returns a dictionary of all the event bindings for a particular
        extension. The configurable keybindings are returned as they exist in
        the dictionary returned by GetCurrentKeySet; that is, where re-used 
        keybindings are disabled.
        """
        bindsName=extensionName+'_bindings'
        extBinds=self.GetExtensionKeys(extensionName)
        #add the non-configurable bindings
        if self.defaultCfg['extensions'].has_section(bindsName):
            eventNames=self.defaultCfg['extensions'].GetOptionList(bindsName)
            for eventName in eventNames:
                binding=self.GetOption('extensions',bindsName,
                        eventName,default='').split()
                event='<<'+eventName+'>>'
                extBinds[event]=binding
        
        return extBinds 
        
    
    
    def GetKeyBinding(self, keySetName, eventStr):
        """
        returns the keybinding for a specific event.
        keySetName - string, name of key binding set
        eventStr - string, the virtual event we want the binding for, 
                   represented as a string, eg. '<<event>>'
        """
        eventName=eventStr[2:-2] #trim off the angle brackets
        binding=self.GetOption('keys',keySetName,eventName,default='').split()
        return binding

    def GetCurrentKeySet(self):
        """
        Returns a dictionary of: all current core keybindings, plus the 
        keybindings for all currently active extensions. If a binding defined
        in an extension is already in use, that binding is disabled.
        """
        currentKeySet=self.GetCoreKeys(keySetName=self.CurrentKeys())
        activeExtns=self.GetExtensions(activeOnly=1)
        for extn in activeExtns:
            extKeys=self.__GetRawExtensionKeys(extn)
            if extKeys: #the extension defines keybindings
                for event in extKeys.keys():
                    if extKeys[event] in currentKeySet.values():
                        #the binding is already in use
                        extKeys[event]='' #disable this binding
                    currentKeySet[event]=extKeys[event] #add binding
        return currentKeySet
    
    def GetCoreKeys(self, keySetName=None):
        """
        returns the requested set of core keybindings, with fallbacks if
        required.
        """
        #keybindings loaded from the config file(s) are loaded _over_ these
        #defaults, so if there is a problem getting any core binding there will
        #be an 'ultimate last resort fallback' to the CUA-ish bindings
        #defined here.
        keyBindings={
            '<<Copy>>': ['<Control-c>', '<Control-C>'],
            '<<Cut>>': ['<Control-x>', '<Control-X>'],
            '<<Paste>>': ['<Control-v>', '<Control-V>'],
            '<<beginning-of-line>>': ['<Control-a>', '<Home>'],
            '<<center-insert>>': ['<Control-l>'],
            '<<close-all-windows>>': ['<Control-q>'],
            '<<close-window>>': ['<Alt-F4>'],
            '<<end-of-file>>': ['<Control-d>'],
            '<<python-docs>>': ['<F1>'],
            '<<python-context-help>>': ['<Shift-F1>'], 
            '<<history-next>>': ['<Alt-n>'],
            '<<history-previous>>': ['<Alt-p>'],
            '<<interrupt-execution>>': ['<Control-c>'],
            '<<open-class-browser>>': ['<Alt-c>'],
            '<<open-module>>': ['<Alt-m>'],
            '<<open-new-window>>': ['<Control-n>'],
            '<<open-window-from-file>>': ['<Control-o>'],
            '<<plain-newline-and-indent>>': ['<Control-j>'],
            '<<redo>>': ['<Control-y>'],
            '<<remove-selection>>': ['<Escape>'],
            '<<save-copy-of-window-as-file>>': ['<Alt-Shift-s>'],
            '<<save-window-as-file>>': ['<Alt-s>'],
            '<<save-window>>': ['<Control-s>'],
            '<<select-all>>': ['<Alt-a>'],
            '<<toggle-auto-coloring>>': ['<Control-slash>'],
            '<<undo>>': ['<Control-z>'],
            '<<find-again>>': ['<Control-g>', '<F3>'],
            '<<find-in-files>>': ['<Alt-F3>'],
            '<<find-selection>>': ['<Control-F3>'],
            '<<find>>': ['<Control-f>'],
            '<<replace>>': ['<Control-h>'],
            '<<goto-line>>': ['<Alt-g>'] }
        
        if keySetName:
            for event in keyBindings.keys():
                binding=self.GetKeyBinding(keySetName,event)
                if binding: #otherwise will keep default
                    keyBindings[event]=binding
            
        return keyBindings

    
    def LoadCfgFiles(self):
        """ 
        load all configuration files.
        """
        for key in self.defaultCfg.keys():
            self.defaultCfg[key].Load()                    
            self.userCfg[key].Load() #same keys                    

    def SaveUserCfgFiles(self):
        """
        write all loaded user configuration files back to disk
        """
        for key in self.userCfg.keys():
            self.userCfg[key].Save()    

idleConf=IdleConf()

### module test
if __name__ == '__main__':
    def dumpCfg(cfg):
        print '\n',cfg,'\n'
        for key in cfg.keys():
            sections=cfg[key].sections()
            print key
            print sections
            for section in sections:
                options=cfg[key].options(section)
                print section    
                print options
                for option in options:
                    print option, '=', cfg[key].Get(section,option)
    dumpCfg(idleConf.defaultCfg)
    dumpCfg(idleConf.userCfg)
    print idleConf.userCfg['main'].Get('Theme','name')
    #print idleConf.userCfg['highlight'].GetDefHighlight('Foo','normal')
