"""
configuration dialog
"""
from Tkinter import *
import tkMessageBox, tkColorChooser, tkFont
import string

from configHandler import idleConf
from dynOptionMenuWidget import DynOptionMenu
from tabpage import TabPageSet
from keybindingDialog import GetKeysDialog

class ConfigDialog(Toplevel):
    """
    configuration dialog for idle
    """ 
    def __init__(self,parent,title):
        Toplevel.__init__(self, parent)
        self.configure(borderwidth=5)
        self.geometry("+%d+%d" % (parent.winfo_rootx()+20,
                parent.winfo_rooty()+30))
        #Theme Elements. Each theme element key is it's display name.
        #The first value of the tuple is the sample area tag name.
        #The second value is the display name list sort index. 
        #The third value indicates whether the element can have a foreground 
        #or background colour or both. 
        self.themeElements={'Normal Text':('normal','00'),
            'Python Keywords':('keyword','01'),
            'Python Definitions':('definition','02'),
            'Python Comments':('comment','03'),
            'Python Strings':('string','04'),
            'Selected Text':('hilite','05'),
            'Found Text':('hit','06'),
            'Cursor':('cursor','07'),
            'Error Text':('error','08'),
            'Shell Normal Text':('console','09'),
            'Shell Stdout Text':('stdout','10'),
            'Shell Stderr Text':('stderr','11')}
        self.CreateWidgets()
        self.resizable(height=FALSE,width=FALSE)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.Cancel)
        self.parent = parent
        self.tabPages.focus_set()
        #key bindings for this dialog
        self.bind('<Escape>',self.CancelBinding) #dismiss dialog, no save
        self.bind('<Alt-a>',self.ApplyBinding) #apply changes, save
        self.bind('<F1>',self.HelpBinding) #context help
        self.LoadConfigs()
        self.wait_window()
        
    def Cancel(self):
        self.destroy()

    def Ok(self):
        pass

    def Apply(self):
        pass

    def Help(self):
        pass

    def CancelBinding(self,event):
        self.Cancel()
    
    def OkBinding(self,event):
        self.Ok()
    
    def ApplyBinding(self,event):
        self.Apply()
    
    def HelpBinding(self,event):
        self.Help()
    
    def SetThemeType(self):
        if self.themeIsBuiltin.get():
            self.optMenuThemeBuiltin.config(state=NORMAL)
            self.optMenuThemeCustom.config(state=DISABLED)
            self.buttonDeleteCustomTheme.config(state=DISABLED)
        else:
            self.optMenuThemeBuiltin.config(state=DISABLED)
            self.optMenuThemeCustom.config(state=NORMAL)
            self.buttonDeleteCustomTheme.config(state=NORMAL)

    def SetKeysType(self):
        if self.keysAreDefault.get():
            self.optMenuKeysBuiltin.config(state=NORMAL)
            self.optMenuKeysCustom.config(state=DISABLED)
            self.buttonDeleteCustomKeys.config(state=DISABLED)
        else:
            self.optMenuKeysBuiltin.config(state=DISABLED)
            self.optMenuKeysCustom.config(state=NORMAL)
            self.buttonDeleteCustomKeys.config(state=NORMAL)
    
    def GetColour(self):
        target=self.highlightTarget.get()
        rgbTuplet, colourString = tkColorChooser.askcolor(parent=self,
            title='Pick new colour for : '+target,
            initialcolor=self.frameColourSet.cget('bg'))
        if colourString: #user didn't cancel
            self.frameColourSet.config(bg=colourString)#set sample
            if self.fgHilite.get(): plane='foreground'
            else: plane='background'
            apply(self.textHighlightSample.tag_config,
                (self.themeElements[target][0],),{plane:colourString})
    
    def SetFontSampleBinding(self,event):
        self.SetFontSample()
        
    def SetFontSample(self):
        self.editFont.config(size=self.fontSize.get(),weight=NORMAL,
            family=self.listFontName.get(self.listFontName.curselection()[0]))

    def SetHighlightTargetBinding(self,*args):
        self.SetHighlightTarget()
        
    def SetHighlightTarget(self):
        if self.highlightTarget.get()=='Cursor': #bg not possible
            self.radioFg.config(state=DISABLED)
            self.radioBg.config(state=DISABLED)
            self.fgHilite.set(1)
        else: #both fg and bg can be set
            self.radioFg.config(state=NORMAL)
            self.radioBg.config(state=NORMAL)
            self.fgHilite.set(1)
        self.SetColourSample()
    
    def SetColourSampleBinding(self,*args):
        self.SetColourSample()
        
    def SetColourSample(self):
        #set the colour smaple area
        tag=self.themeElements[self.highlightTarget.get()][0]
        if self.fgHilite.get(): plane='foreground'
        else: plane='background'
        colour=self.textHighlightSample.tag_cget(tag,plane)
        self.frameColourSet.config(bg=colour)
    
    def CreateWidgets(self):
        self.tabPages = TabPageSet(self,
                pageNames=['Fonts/Tabs','Highlighting','Keys','General'])
        self.tabPages.ChangePage()#activates default (first) page
        frameActionButtons = Frame(self)
        #action buttons
        self.buttonHelp = Button(frameActionButtons,text='Help',
                command=self.Help,takefocus=FALSE)
        self.buttonOk = Button(frameActionButtons,text='Ok',
                command=self.Ok,takefocus=FALSE)
        self.buttonApply = Button(frameActionButtons,text='Apply',
                command=self.Apply,underline=0,takefocus=FALSE)
        self.buttonCancel = Button(frameActionButtons,text='Cancel',
                command=self.Cancel,takefocus=FALSE)
        self.CreatePageFontTab()
        self.CreatePageHighlight()
        self.CreatePageKeys()
        self.CreatePageGeneral()
        self.buttonHelp.pack(side=RIGHT,padx=5,pady=5)
        self.buttonOk.pack(side=LEFT,padx=5,pady=5)
        self.buttonApply.pack(side=LEFT,padx=5,pady=5)
        self.buttonCancel.pack(side=LEFT,padx=5,pady=5)
        frameActionButtons.pack(side=BOTTOM)
        self.tabPages.pack(side=TOP,expand=TRUE,fill=BOTH)

        
    def CreatePageFontTab(self):
        #tkVars
        self.fontSize=StringVar(self)
        self.fontBold=StringVar(self)
        self.spaceNum=IntVar(self)
        self.tabCols=IntVar(self)
        self.indentType=IntVar(self) 
        self.editFont=tkFont.Font(self,('courier',12,'normal'))
        ##widget creation
        #body frame
        frame=self.tabPages.pages['Fonts/Tabs']['page']
        #body section frames
        frameFont=Frame(frame,borderwidth=2,relief=GROOVE)
        frameIndent=Frame(frame,borderwidth=2,relief=GROOVE)
        #frameFont
        labelFontTitle=Label(frameFont,text='Set Base Editor Font')
        frameFontName=Frame(frameFont)
        frameFontParam=Frame(frameFont)
        labelFontNameTitle=Label(frameFontName,justify=LEFT,
                text='Font :')
        self.listFontName=Listbox(frameFontName,height=5,takefocus=FALSE,
                exportselection=FALSE)
        self.listFontName.bind('<<ListboxSelect>>',self.SetFontSampleBinding)
        scrollFont=Scrollbar(frameFontName)
        scrollFont.config(command=self.listFontName.yview)
        self.listFontName.config(yscrollcommand=scrollFont.set)
        labelFontSizeTitle=Label(frameFontParam,text='Size :')
        self.optMenuFontSize=DynOptionMenu(frameFontParam,self.fontSize,None,
            command=self.SetFontSampleBinding)
        checkFontBold=Checkbutton(frameFontParam,variable=self.fontBold,
            onvalue='Bold',offvalue='',text='Bold')
        frameFontSample=Frame(frameFont,relief=SOLID,borderwidth=1)
        self.labelFontSample=Label(frameFontSample,
                text='AaBbCcDdEe\nFfGgHhIiJjK\n1234567890\n#:+=(){}[]',
                justify=LEFT,font=self.editFont)
        #frameIndent
        labelIndentTitle=Label(frameIndent,text='Set Indentation Defaults')
        frameIndentType=Frame(frameIndent)
        frameIndentSize=Frame(frameIndent)
        labelIndentTypeTitle=Label(frameIndentType,
                text='Choose indentation type :')
        radioUseSpaces=Radiobutton(frameIndentType,variable=self.indentType,
            value=1,text='Tab key inserts spaces')
        radioUseTabs=Radiobutton(frameIndentType,variable=self.indentType,
            value=0,text='Tab key inserts tabs')
        labelIndentSizeTitle=Label(frameIndentSize,
                text='Choose indentation size :')
        labelSpaceNumTitle=Label(frameIndentSize,justify=LEFT,
                text='when tab key inserts spaces,\nspaces per tab')
        self.scaleSpaceNum=Scale(frameIndentSize,variable=self.spaceNum,
                orient='horizontal',tickinterval=2,from_=2,to=8)
        labeltabColsTitle=Label(frameIndentSize,justify=LEFT,
                text='when tab key inserts tabs,\ncolumns per tab')
        self.scaleTabCols=Scale(frameIndentSize,variable=self.tabCols,
                orient='horizontal',tickinterval=2,from_=2,to=8)
        #widget packing
        #body
        frameFont.pack(side=LEFT,padx=5,pady=10,expand=TRUE,fill=BOTH)
        frameIndent.pack(side=LEFT,padx=5,pady=10,fill=Y)
        #frameFont
        labelFontTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        frameFontName.pack(side=TOP,padx=5,pady=5,fill=X)
        frameFontParam.pack(side=TOP,padx=5,pady=5,fill=X)
        labelFontNameTitle.pack(side=TOP,anchor=W)
        self.listFontName.pack(side=LEFT,expand=TRUE,fill=X)
        scrollFont.pack(side=LEFT,fill=Y)
        labelFontSizeTitle.pack(side=LEFT,anchor=W)
        self.optMenuFontSize.pack(side=LEFT,anchor=W)
        checkFontBold.pack(side=LEFT,anchor=W,padx=20)
        frameFontSample.pack(side=TOP,padx=5,pady=5,expand=TRUE,fill=BOTH)
        self.labelFontSample.pack(expand=TRUE,fill=BOTH)
        #frameIndent
        labelIndentTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        frameIndentType.pack(side=TOP,padx=5,fill=X)
        frameIndentSize.pack(side=TOP,padx=5,pady=5,fill=BOTH)
        labelIndentTypeTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        radioUseSpaces.pack(side=TOP,anchor=W,padx=5)
        radioUseTabs.pack(side=TOP,anchor=W,padx=5)
        labelIndentSizeTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        labelSpaceNumTitle.pack(side=TOP,anchor=W,padx=5)
        self.scaleSpaceNum.pack(side=TOP,padx=5,fill=X)
        labeltabColsTitle.pack(side=TOP,anchor=W,padx=5)
        self.scaleTabCols.pack(side=TOP,padx=5,fill=X)
        return frame

    def CreatePageHighlight(self):
        self.builtinTheme=StringVar(self)
        self.customTheme=StringVar(self)
        self.fgHilite=IntVar(self)
        self.colour=StringVar(self)
        self.fontName=StringVar(self)
        self.themeIsBuiltin=IntVar(self) 
        self.highlightTarget=StringVar(self)
        self.highlightTarget.trace_variable('w',self.SetHighlightTargetBinding)
        ##widget creation
        #body frame
        frame=self.tabPages.pages['Highlighting']['page']
        #body section frames
        frameCustom=Frame(frame,borderwidth=2,relief=GROOVE)
        frameTheme=Frame(frame,borderwidth=2,relief=GROOVE)
        #frameCustom
        self.textHighlightSample=Text(frameCustom,relief=SOLID,borderwidth=1,
            font=('courier',12,''),cursor='hand2',width=10,height=10,
            takefocus=FALSE,highlightthickness=0)
        text=self.textHighlightSample
        text.bind('<Double-Button-1>',lambda e: 'break')
        text.bind('<B1-Motion>',lambda e: 'break')
        textAndTags=(('#you can click in here','comment'),('\n','normal'),
            ('#to choose items','comment'),('\n','normal'),('def','keyword'),
            (' ','normal'),('func','definition'),('(param):','normal'),
            ('\n  ','normal'),('"""string"""','string'),('\n  var0 = ','normal'),
            ("'string'",'string'),('\n  var1 = ','normal'),("'selected'",'hilite'),
            ('\n  var2 = ','normal'),("'found'",'hit'),('\n\n','normal'),
            (' error ','error'),(' ','normal'),('cursor |','cursor'),
            ('\n ','normal'),('shell','console'),(' ','normal'),('stdout','stdout'),
            (' ','normal'),('stderr','stderr'),('\n','normal'))
        for txTa in textAndTags:
            text.insert(END,txTa[0],txTa[1])
        for element in self.themeElements.keys(): 
            text.tag_bind(self.themeElements[element][0],'<ButtonPress-1>',
                lambda event,elem=element: event.widget.winfo_toplevel()
                .highlightTarget.set(elem))
        text.config(state=DISABLED)
        self.frameColourSet=Frame(frameCustom,relief=SOLID,borderwidth=1)
        frameFgBg=Frame(frameCustom)
        labelCustomTitle=Label(frameCustom,text='Set Custom Highlighting')
        buttonSetColour=Button(self.frameColourSet,text='Choose Colour for :',
            command=self.GetColour,highlightthickness=0)
        self.optMenuHighlightTarget=DynOptionMenu(self.frameColourSet,
            self.highlightTarget,None,highlightthickness=0)#,command=self.SetHighlightTargetBinding
        self.radioFg=Radiobutton(frameFgBg,variable=self.fgHilite,
            value=1,text='Foreground',command=self.SetColourSampleBinding)
        self.radioBg=Radiobutton(frameFgBg,variable=self.fgHilite,
            value=0,text='Background',command=self.SetColourSampleBinding)
        self.fgHilite.set(1)
        buttonSaveCustomTheme=Button(frameCustom, 
            text='Save as a Custom Theme')
        #frameTheme
        labelThemeTitle=Label(frameTheme,text='Select a Highlighting Theme')
        labelTypeTitle=Label(frameTheme,text='Select : ')
        self.radioThemeBuiltin=Radiobutton(frameTheme,variable=self.themeIsBuiltin,
            value=1,command=self.SetThemeType,text='a Built-in Theme')
        self.radioThemeCustom=Radiobutton(frameTheme,variable=self.themeIsBuiltin,
            value=0,command=self.SetThemeType,text='a Custom Theme')
        self.optMenuThemeBuiltin=DynOptionMenu(frameTheme,
            self.builtinTheme,None,command=None)
        self.optMenuThemeCustom=DynOptionMenu(frameTheme,
            self.customTheme,None,command=None)
        self.buttonDeleteCustomTheme=Button(frameTheme,text='Delete Custom Theme')
        ##widget packing
        #body
        frameCustom.pack(side=LEFT,padx=5,pady=10,expand=TRUE,fill=BOTH)
        frameTheme.pack(side=LEFT,padx=5,pady=10,fill=Y)
        #frameCustom
        labelCustomTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        self.frameColourSet.pack(side=TOP,padx=5,pady=5,expand=TRUE,fill=X)
        frameFgBg.pack(side=TOP,padx=5,pady=0)
        self.textHighlightSample.pack(side=TOP,padx=5,pady=5,expand=TRUE,
            fill=BOTH)
        buttonSetColour.pack(side=TOP,expand=TRUE,fill=X,padx=8,pady=4)
        self.optMenuHighlightTarget.pack(side=TOP,expand=TRUE,fill=X,padx=8,pady=3)
        self.radioFg.pack(side=LEFT,anchor=E)
        self.radioBg.pack(side=RIGHT,anchor=W)
        buttonSaveCustomTheme.pack(side=BOTTOM,fill=X,padx=5,pady=5)        
        #frameTheme
        labelThemeTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        labelTypeTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        self.radioThemeBuiltin.pack(side=TOP,anchor=W,padx=5)
        self.radioThemeCustom.pack(side=TOP,anchor=W,padx=5,pady=2)
        self.optMenuThemeBuiltin.pack(side=TOP,fill=X,padx=5,pady=5)
        self.optMenuThemeCustom.pack(side=TOP,fill=X,anchor=W,padx=5,pady=5)
        self.buttonDeleteCustomTheme.pack(side=TOP,fill=X,padx=5,pady=5)
        return frame

    def CreatePageKeys(self):
        #tkVars
        self.bindingTarget=StringVar(self)
        self.builtinKeys=StringVar(self)
        self.customKeys=StringVar(self)
        self.keyChars=StringVar(self)
        self.keyCtrl=StringVar(self)
        self.keyAlt=StringVar(self)
        self.keyShift=StringVar(self)
        self.keysAreDefault=IntVar(self) 
        ##widget creation
        #body frame
        frame=self.tabPages.pages['Keys']['page']
        #body section frames
        frameCustom=Frame(frame,borderwidth=2,relief=GROOVE)
        frameKeySets=Frame(frame,borderwidth=2,relief=GROOVE)
        #frameCustom
        frameTarget=Frame(frameCustom)
        labelCustomTitle=Label(frameCustom,text='Set Custom Key Bindings')
        labelTargetTitle=Label(frameTarget,text='Action - Key(s)')
        scrollTargetY=Scrollbar(frameTarget)
        scrollTargetX=Scrollbar(frameTarget,orient=HORIZONTAL)
        self.listBindings=Listbox(frameTarget)
        scrollTargetY.config(command=self.listBindings.yview)
        scrollTargetX.config(command=self.listBindings.xview)
        self.listBindings.config(yscrollcommand=scrollTargetY.set)
        self.listBindings.config(xscrollcommand=scrollTargetX.set)
        buttonNewKeys=Button(frameCustom,text='Get New Keys for Selection',
            command=self.GetNewKeys)
        buttonSaveCustomKeys=Button(frameCustom,text='Save as a Custom Key Set')
        #frameKeySets
        labelKeysTitle=Label(frameKeySets,text='Select a Key Set')
        labelTypeTitle=Label(frameKeySets,text='Select : ')
        self.radioKeysBuiltin=Radiobutton(frameKeySets,variable=self.keysAreDefault,
            value=1,command=self.SetKeysType,text='a Built-in Key Set')
        self.radioKeysCustom=Radiobutton(frameKeySets,variable=self.keysAreDefault,
            value=0,command=self.SetKeysType,text='a Custom Key Set')
        self.optMenuKeysBuiltin=DynOptionMenu(frameKeySets,
            self.builtinKeys,None,command=None)
        self.optMenuKeysCustom=DynOptionMenu(frameKeySets,
            self.customKeys,None,command=None)
        self.buttonDeleteCustomKeys=Button(frameKeySets,text='Delete Custom Key Set')
        ##widget packing
        #body
        frameCustom.pack(side=LEFT,padx=5,pady=5,expand=TRUE,fill=BOTH)
        frameKeySets.pack(side=LEFT,padx=5,pady=5,fill=Y)
        #frameCustom
        labelCustomTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        buttonSaveCustomKeys.pack(side=BOTTOM,fill=X,padx=5,pady=5)        
        buttonNewKeys.pack(side=BOTTOM,fill=X,padx=5,pady=5)        
        frameTarget.pack(side=LEFT,padx=5,pady=5,expand=TRUE,fill=BOTH)
        #frame target
        frameTarget.columnconfigure(0,weight=1)
        frameTarget.rowconfigure(1,weight=1)
        labelTargetTitle.grid(row=0,column=0,columnspan=2,sticky=W)
        self.listBindings.grid(row=1,column=0,sticky=NSEW)
        scrollTargetY.grid(row=1,column=1,sticky=NS)
        scrollTargetX.grid(row=2,column=0,sticky=EW)
        #frameKeySets
        labelKeysTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        labelTypeTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        self.radioKeysBuiltin.pack(side=TOP,anchor=W,padx=5)
        self.radioKeysCustom.pack(side=TOP,anchor=W,padx=5,pady=2)
        self.optMenuKeysBuiltin.pack(side=TOP,fill=X,padx=5,pady=5)
        self.optMenuKeysCustom.pack(side=TOP,fill=X,anchor=W,padx=5,pady=5)
        self.buttonDeleteCustomKeys.pack(side=TOP,fill=X,padx=5,pady=5)
        return frame

    def CreatePageGeneral(self):
        #tkVars        
        self.runType=IntVar(self)       
        self.winWidth=StringVar(self)       
        self.winHeight=StringVar(self)
        self.extState=IntVar(self)       
        #widget creation
        #body
        frame=self.tabPages.pages['General']['page']
        #body section frames        
        frameRun=Frame(frame,borderwidth=2,relief=GROOVE)
        frameWinSize=Frame(frame,borderwidth=2,relief=GROOVE)
        frameExt=Frame(frame,borderwidth=2,relief=GROOVE)
        #frameRun
        labelRunTitle=Label(frameRun,text='Run Preferences')
        labelRunChoiceTitle=Label(frameRun,text='Run code : ')
        radioRunInternal=Radiobutton(frameRun,variable=self.runType,
            value=0,command=self.SetKeysType,text="in IDLE's Process")
        radioRunSeparate=Radiobutton(frameRun,variable=self.runType,
            value=1,command=self.SetKeysType,text='in a Separate Process')
        #frameWinSize
        labelWinSizeTitle=Label(frameWinSize,text='Initial Window Size')
        labelWinWidthTitle=Label(frameWinSize,text='Width')
        entryWinWidth=Entry(frameWinSize,textvariable=self.winWidth,
                width=3)
        labelWinHeightTitle=Label(frameWinSize,text='Height')
        entryWinHeight=Entry(frameWinSize,textvariable=self.winHeight,
                width=3)
        #frameExt
        frameExtList=Frame(frameExt)
        frameExtSet=Frame(frameExt)
        labelExtTitle=Label(frameExt,text='Configure IDLE Extensions')
        labelExtListTitle=Label(frameExtList,text='Extension')
        scrollExtList=Scrollbar(frameExtList)
        listExt=Listbox(frameExtList,height=5)
        scrollExtList.config(command=listExt.yview)
        listExt.config(yscrollcommand=scrollExtList.set)
        labelExtSetTitle=Label(frameExtSet,text='Settings')
        radioEnableExt=Radiobutton(frameExtSet,variable=self.extState,
            value=1,text="enable")
        radioDisableExt=Radiobutton(frameExtSet,variable=self.extState,
            value=0,text="disable")
        self.extState.set(1)
        buttonExtConfig=Button(frameExtSet,text='Configure')
        
        #widget packing
        #body
        frameRun.pack(side=TOP,padx=5,pady=5,fill=X)
        frameWinSize.pack(side=TOP,padx=5,pady=5,fill=X)
        frameExt.pack(side=TOP,padx=5,pady=5,expand=TRUE,fill=BOTH)
        #frameRun
        labelRunTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        labelRunChoiceTitle.pack(side=LEFT,anchor=W,padx=5,pady=5)
        radioRunInternal.pack(side=LEFT,anchor=W,padx=5,pady=5)
        radioRunSeparate.pack(side=LEFT,anchor=W,padx=5,pady=5)     
        #frameWinSize
        labelWinSizeTitle.pack(side=LEFT,anchor=W,padx=5,pady=5)
        entryWinHeight.pack(side=RIGHT,anchor=E,padx=10,pady=5)
        labelWinHeightTitle.pack(side=RIGHT,anchor=E,pady=5)
        entryWinWidth.pack(side=RIGHT,anchor=E,padx=10,pady=5)
        labelWinWidthTitle.pack(side=RIGHT,anchor=E,pady=5)
        #frameExt
        labelExtTitle.pack(side=TOP,anchor=W,padx=5,pady=5)
        frameExtSet.pack(side=RIGHT,padx=5,pady=5,fill=Y)
        frameExtList.pack(side=RIGHT,padx=5,pady=5,expand=TRUE,fill=BOTH)
        labelExtListTitle.pack(side=TOP,anchor=W)
        scrollExtList.pack(side=RIGHT,anchor=W,fill=Y)
        listExt.pack(side=LEFT,anchor=E,expand=TRUE,fill=BOTH)
        labelExtSetTitle.pack(side=TOP,anchor=W)
        radioEnableExt.pack(side=TOP,anchor=W)
        radioDisableExt.pack(side=TOP,anchor=W)
        buttonExtConfig.pack(side=TOP,anchor=W,pady=5)

        return frame

    def PaintThemeSample(self):
        if self.themeIsBuiltin.get(): #a default theme
            theme=self.builtinTheme.get()
        else: #a user theme
            theme=self.customTheme.get()
        for element in self.themeElements.keys():
            colours=idleConf.GetHighlight(theme, self.themeElements[element][0])
            if element=='Cursor': #cursor sample needs special painting
                colours['background']=idleConf.GetHighlight(theme, 
                        'normal', fgBg='bg')
            apply(self.textHighlightSample.tag_config,
                (self.themeElements[element][0],),colours)
    
    def LoadFontCfg(self):
        ##base editor font selection list
        fonts=list(tkFont.families(self))
        fonts.sort()
        for font in fonts:
            self.listFontName.insert(END,font)
        configuredFont=idleConf.GetOption('main','EditorWindow','font',
                default='courier')
        if configuredFont in fonts:
            currentFontIndex=fonts.index(configuredFont)
            self.listFontName.see(currentFontIndex)
            self.listFontName.select_set(currentFontIndex)
        ##font size dropdown
        fontSize=idleConf.GetOption('main','EditorWindow','font-size',default='12')
        self.optMenuFontSize.SetMenu(('10','11','12','13','14',
                '16','18','20','22'),fontSize )
        ##font sample 
        self.SetFontSample()
    
    def LoadTabCfg(self):
        ##indent type radibuttons
        spaceIndent=idleConf.GetOption('main','Indent','use-spaces',
                default=1,type='bool')
        self.indentType.set(spaceIndent)
        ##indent sizes
        spaceNum=idleConf.GetOption('main','Indent','num-spaces',
                default=4,type='int')
        tabCols=idleConf.GetOption('main','Indent','tab-cols',
                default=4,type='int')
        self.spaceNum.set(spaceNum)
        self.tabCols.set(tabCols)
    
    def LoadThemeCfg(self):
        ##current theme type radiobutton
        self.themeIsBuiltin.set(idleConf.GetOption('main','Theme','default',
            type='int',default=1))
        ##currently set theme
        currentOption=idleConf.CurrentTheme()
        ##load available theme option menus
        if self.themeIsBuiltin.get(): #default theme selected
            itemList=idleConf.GetSectionList('default','highlight')
            self.optMenuThemeBuiltin.SetMenu(itemList,currentOption)
            itemList=idleConf.GetSectionList('user','highlight')
            if not itemList:
                self.radioThemeCustom.config(state=DISABLED)
                self.customTheme.set('- no custom themes -')    
            else:
                self.optMenuThemeCustom.SetMenu(itemList,itemList[0])
        else: #user theme selected
            itemList=idleConf.GetSectionList('user','highlight')
            self.optMenuThemeCustom.SetMenu(itemList,currentOption)
            itemList=idleConf.GetSectionList('default','highlight')
            self.optMenuThemeBuiltin.SetMenu(itemList,itemList[0])
        self.SetThemeType()
        ##load theme element option menu
        themeNames=self.themeElements.keys()
        themeNames.sort(self.__ThemeNameIndexCompare)
        self.optMenuHighlightTarget.SetMenu(themeNames,themeNames[0])   
        self.PaintThemeSample()
        self.SetHighlightTarget()
    
    def __ThemeNameIndexCompare(self,a,b):
        if self.themeElements[a][1]<self.themeElements[b][1]: return -1
        elif self.themeElements[a][1]==self.themeElements[b][1]: return 0
        else: return 1
    
    def LoadKeyCfg(self):
        ##current keys type radiobutton
        self.keysAreDefault.set(idleConf.GetOption('main','Keys','default',
            type='int',default=1))
        ##currently set keys
        currentOption=idleConf.CurrentKeys()
        ##load available keyset option menus
        if self.keysAreDefault.get(): #default theme selected
            itemList=idleConf.GetSectionList('default','keys')
            self.optMenuKeysBuiltin.SetMenu(itemList,currentOption)
            itemList=idleConf.GetSectionList('user','keys')
            if not itemList:
                self.radioKeysCustom.config(state=DISABLED)    
                self.customKeys.set('- no custom keys -')    
            else:
                self.optMenuKeysCustom.SetMenu(itemList,itemList[0])
        else: #user theme selected
            itemList=idleConf.GetSectionList('user','keys')
            self.optMenuKeysCustom.SetMenu(itemList,currentOption)
            itemList=idleConf.GetSectionList('default','keys')
            self.optMenuKeysBuiltin.SetMenu(itemList,itemList[0])
        self.SetKeysType()   
        ##load keyset element list
        keySet=idleConf.GetKeys(currentOption)
        bindNames=keySet.keys()
        bindNames.sort()
        for bindName in bindNames: 
            key=string.join(keySet[bindName]) #make key(s) into a string
            bindName=bindName[2:-2] #trim off the angle brackets
            self.listBindings.insert(END, bindName+' - '+key)
   
    def GetNewKeys(self):
        listIndex=self.listBindings.index(ANCHOR)
        binding=self.listBindings.get(listIndex)
        bindName=binding.split()[0] #first part, up to first space
        newKeys=GetKeysDialog(self,'Get New Keys',bindName)
        print newKeys.result
        if newKeys.result: #new keys were specified
            self.listBindings.delete(listIndex)
            self.listBindings.insert(listIndex,bindName+' - '+newKeys.result)
        self.listBindings.select_set(listIndex)
    
    def LoadGeneralCfg(self):
        #initial window size
        self.winWidth.set(idleConf.GetOption('main','EditorWindow','width'))       
        self.winHeight.set(idleConf.GetOption('main','EditorWindow','height'))
        
        
    def LoadConfigs(self):
        """
        load configuration from default and user config files and populate
        the widgets on the config dialog pages.
        """
        ### fonts / tabs page
        self.LoadFontCfg()        
        self.LoadTabCfg()        
        ### highlighting page
        self.LoadThemeCfg()
        ### keys page
        self.LoadKeyCfg()
        ### help page
        ### general page
        self.LoadGeneralCfg()
        
    def SaveConfigs(self):
        """
        save configuration changes to user config files.
        """
        pass

if __name__ == '__main__':
    #test the dialog
    root=Tk()
    Button(root,text='Dialog',
            command=lambda:ConfigDialog(root,'Settings')).pack()
    root.mainloop()
