import string
from Tkinter import TclError
import tkMessageBox
import tkSimpleDialog

# The default tab setting for a Text widget, in average-width characters.
TK_TABWIDTH_DEFAULT = 8

###$ event <<newline-and-indent>>
###$ win <Key-Return>
###$ win <KP_Enter>
###$ unix <Key-Return>
###$ unix <KP_Enter>

###$ event <<indent-region>>
###$ win <Control-bracketright>
###$ unix <Alt-bracketright>
###$ unix <Control-bracketright>

###$ event <<dedent-region>>
###$ win <Control-bracketleft>
###$ unix <Alt-bracketleft>
###$ unix <Control-bracketleft>

###$ event <<comment-region>>
###$ win <Alt-Key-3>
###$ unix <Alt-Key-3>

###$ event <<uncomment-region>>
###$ win <Alt-Key-4>
###$ unix <Alt-Key-4>

###$ event <<tabify-region>>
###$ win <Alt-Key-5>
###$ unix <Alt-Key-5>

###$ event <<untabify-region>>
###$ win <Alt-Key-6>
###$ unix <Alt-Key-6>

class AutoIndent:

    menudefs = [
        ('edit', [
            None,
            ('_Indent region', '<<indent-region>>'),
            ('_Dedent region', '<<dedent-region>>'),
            ('Comment _out region', '<<comment-region>>'),
            ('U_ncomment region', '<<uncomment-region>>'),
            ('Tabify region', '<<tabify-region>>'),
            ('Untabify region', '<<untabify-region>>'),
            ('Toggle tabs', '<<toggle-tabs>>'),
            ('New indent width', '<<change-indentwidth>>'),
        ]),
    ]

    keydefs = {
        '<<smart-backspace>>': ['<Key-BackSpace>'],
        '<<newline-and-indent>>': ['<Key-Return>', '<KP_Enter>'],
        '<<smart-indent>>': ['<Key-Tab>']
    }

    windows_keydefs = {
        '<<indent-region>>': ['<Control-bracketright>'],
        '<<dedent-region>>': ['<Control-bracketleft>'],
        '<<comment-region>>': ['<Alt-Key-3>'],
        '<<uncomment-region>>': ['<Alt-Key-4>'],
        '<<tabify-region>>': ['<Alt-Key-5>'],
        '<<untabify-region>>': ['<Alt-Key-6>'],
        '<<toggle-tabs>>': ['<Alt-Key-t>'],
        '<<change-indentwidth>>': ['<Alt-Key-u>'],
    }

    unix_keydefs = {
        '<<indent-region>>': ['<Alt-bracketright>',
                              '<Meta-bracketright>',
                              '<Control-bracketright>'],
        '<<dedent-region>>': ['<Alt-bracketleft>',
                              '<Meta-bracketleft>',
                              '<Control-bracketleft>'],
        '<<comment-region>>': ['<Alt-Key-3>', '<Meta-Key-3>'],
        '<<uncomment-region>>': ['<Alt-Key-4>', '<Meta-Key-4>'],
        '<<tabify-region>>': ['<Alt-Key-5>', '<Meta-Key-5>'],
        '<<untabify-region>>': ['<Alt-Key-6>', '<Meta-Key-6>'],
    }

    # usetabs true  -> literal tab characters are used by indent and
    #                  dedent cmds, possibly mixed with spaces if
    #                  indentwidth is not a multiple of tabwidth
    #         false -> tab characters are converted to spaces by indent
    #                  and dedent cmds, and ditto TAB keystrokes
    # indentwidth is the number of characters per logical indent level.
    # tabwidth is the display width of a literal tab character.
    # CAUTION:  telling Tk to use anything other than its default
    # tab setting causes it to use an entirely different tabbing algorithm,
    # treating tab stops as fixed distances from the left margin.
    # Nobody expects this, so for now tabwidth should never be changed.
    usetabs = 0
    indentwidth = 4
    tabwidth = TK_TABWIDTH_DEFAULT

    def __init__(self, editwin):
        self.text = editwin.text

    def config(self, **options):
        for key, value in options.items():
            if key == 'usetabs':
                self.usetabs = value
            elif key == 'indentwidth':
                self.indentwidth = value
            elif key == 'tabwidth':
                self.tabwidth = value
            else:
                raise KeyError, "bad option name: %s" % `key`

    # If ispythonsource and guess are true, guess a good value for
    # indentwidth based on file content (if possible), and if
    # indentwidth != tabwidth set usetabs false.
    # In any case, adjust the Text widget's view of what a tab
    # character means.

    def set_indentation_params(self, ispythonsource, guess=1):
        text = self.text

        if guess and ispythonsource:
            i = self.guess_indent()
            if 2 <= i <= 8:
                self.indentwidth = i
            if self.indentwidth != self.tabwidth:
                self.usetabs = 0

        current_tabs = text['tabs']
        if current_tabs == "" and self.tabwidth == TK_TABWIDTH_DEFAULT:
            pass
        else:
            # Reconfigure the Text widget by measuring the width
            # of a tabwidth-length string in pixels, forcing the
            # widget's tab stops to that.
            need_tabs = text.tk.call("font", "measure", text['font'],
                                     "-displayof", text.master,
                                     "n" * self.tabwidth)
            if current_tabs != need_tabs:
                text.configure(tabs=need_tabs)

    def smart_backspace_event(self, event):
        text = self.text
        try:
            first = text.index("sel.first")
            last = text.index("sel.last")
        except TclError:
            first = last = None
        if first and last:
            text.delete(first, last)
            text.mark_set("insert", first)
            return "break"
        # If we're at the end of leading whitespace, nuke one indent
        # level, else one character.
        chars = text.get("insert linestart", "insert")
        raw, effective = classifyws(chars, self.tabwidth)
        if 0 < raw == len(chars):
            if effective >= self.indentwidth:
                self.reindent_to(effective - self.indentwidth)
                return "break"
        text.delete("insert-1c")
        return "break"

    def smart_indent_event(self, event):
        # if intraline selection:
        #     delete it
        # elif multiline selection:
        #     do indent-region & return
        # indent one level
        text = self.text
        try:
            first = text.index("sel.first")
            last = text.index("sel.last")
        except TclError:
            first = last = None
        text.undo_block_start()
        try:
            if first and last:
                if index2line(first) != index2line(last):
                    return self.indent_region_event(event)
                text.delete(first, last)
                text.mark_set("insert", first)
            prefix = text.get("insert linestart", "insert")
            raw, effective = classifyws(prefix, self.tabwidth)
            if raw == len(prefix):
                # only whitespace to the left
                self.reindent_to(effective + self.indentwidth)
            else:
                if self.usetabs:
                    pad = '\t'
                else:
                    effective = len(string.expandtabs(prefix,
                                                      self.tabwidth))
                    n = self.indentwidth
                    pad = ' ' * (n - effective % n)
                text.insert("insert", pad)
            text.see("insert")
            return "break"
        finally:
            text.undo_block_stop()

    def newline_and_indent_event(self, event):
        text = self.text
        try:
            first = text.index("sel.first")
            last = text.index("sel.last")
        except TclError:
            first = last = None
        text.undo_block_start()
        try:
            if first and last:
                text.delete(first, last)
                text.mark_set("insert", first)
            line = text.get("insert linestart", "insert")
            i, n = 0, len(line)
            while i < n and line[i] in " \t":
                i = i+1
            indent = line[:i]
            # strip trailing whitespace
            i = 0
            while line and line[-1] in " \t":
                line = line[:-1]
                i = i + 1
            if i:
                text.delete("insert - %d chars" % i, "insert")
            # XXX this reproduces the current line's indentation,
            # without regard for usetabs etc; could instead insert
            # "\n" + self._make_blanks(classifyws(indent)[1]).
            text.insert("insert", "\n" + indent)

            # adjust indentation for continuations and block open/close
            x = LineStudier(line)
            if x.is_block_opener():
                self.smart_indent_event(event)
            elif x.is_bracket_continued():
                # if there's something interesting after the last open
                # bracket, line up with it; else just indent one level
                i = x.last_open_bracket_index() + 1
                while i < n and line[i] in " \t":
                    i = i + 1
                if i < n and line[i] not in "#\n\\":
                    effective = len(string.expandtabs(line[:i],
                                                      self.tabwidth))
                else:
                    raw, effective = classifyws(indent, self.tabwidth)
                    effective = effective + self.indentwidth
                self.reindent_to(effective)
            elif x.is_backslash_continued():
                # local info isn't enough to do anything intelligent here;
                # e.g., if it's the 2nd line a backslash block we want to
                # indent extra, but if it's the 3rd we don't want to indent
                # at all; rather than make endless mistakes, leave it alone
                pass
            elif indent and x.is_block_closer():
                self.smart_backspace_event(event)
            text.see("insert")
            return "break"
        finally:
            text.undo_block_stop()

    auto_indent = newline_and_indent_event

    def indent_region_event(self, event):
        head, tail, chars, lines = self.get_region()
        for pos in range(len(lines)):
            line = lines[pos]
            if line:
                raw, effective = classifyws(line, self.tabwidth)
                effective = effective + self.indentwidth
                lines[pos] = self._make_blanks(effective) + line[raw:]
        self.set_region(head, tail, chars, lines)
        return "break"

    def dedent_region_event(self, event):
        head, tail, chars, lines = self.get_region()
        for pos in range(len(lines)):
            line = lines[pos]
            if line:
                raw, effective = classifyws(line, self.tabwidth)
                effective = max(effective - self.indentwidth, 0)
                lines[pos] = self._make_blanks(effective) + line[raw:]
        self.set_region(head, tail, chars, lines)
        return "break"

    def comment_region_event(self, event):
        head, tail, chars, lines = self.get_region()
        for pos in range(len(lines)):
            line = lines[pos]
            if line:
                lines[pos] = '##' + line
        self.set_region(head, tail, chars, lines)

    def uncomment_region_event(self, event):
        head, tail, chars, lines = self.get_region()
        for pos in range(len(lines)):
            line = lines[pos]
            if not line:
                continue
            if line[:2] == '##':
                line = line[2:]
            elif line[:1] == '#':
                line = line[1:]
            lines[pos] = line
        self.set_region(head, tail, chars, lines)

    def tabify_region_event(self, event):
        head, tail, chars, lines = self.get_region()
        tabwidth = self._asktabwidth()
        for pos in range(len(lines)):
            line = lines[pos]
            if line:
                raw, effective = classifyws(line, tabwidth)
                ntabs, nspaces = divmod(effective, tabwidth)
                lines[pos] = '\t' * ntabs + ' ' * nspaces + line[raw:]
        self.set_region(head, tail, chars, lines)

    def untabify_region_event(self, event):
        head, tail, chars, lines = self.get_region()
        tabwidth = self._asktabwidth()
        for pos in range(len(lines)):
            lines[pos] = string.expandtabs(lines[pos], tabwidth)
        self.set_region(head, tail, chars, lines)

    def toggle_tabs_event(self, event):
        if tkMessageBox.askyesno(
              "Toggle tabs",
              "Turn tabs " + ("on", "off")[self.usetabs] + "?",
              parent=self.text):
            self.usetabs = not self.usetabs
        return "break"

    # XXX this isn't bound to anything -- see class tabwidth comments
    def change_tabwidth_event(self, event):
        new = self._asktabwidth()
        if new != self.tabwidth:
            self.tabwidth = new
            self.set_indentation_params(0, guess=0)
        return "break"

    def change_indentwidth_event(self, event):
        new = tkSimpleDialog.askinteger(
                  "Indent width",
                  "New indent width (1-16)",
                  parent=self.text,
                  initialvalue=self.indentwidth,
                  minvalue=1,
                  maxvalue=16)
        if new and new != self.indentwidth:
            self.indentwidth = new
        return "break"

    def get_region(self):
        text = self.text
        head = text.index("sel.first linestart")
        tail = text.index("sel.last -1c lineend +1c")
        if not (head and tail):
            head = text.index("insert linestart")
            tail = text.index("insert lineend +1c")
        chars = text.get(head, tail)
        lines = string.split(chars, "\n")
        return head, tail, chars, lines

    def set_region(self, head, tail, chars, lines):
        text = self.text
        newchars = string.join(lines, "\n")
        if newchars == chars:
            text.bell()
            return
        text.tag_remove("sel", "1.0", "end")
        text.mark_set("insert", head)
        text.undo_block_start()
        text.delete(head, tail)
        text.insert(head, newchars)
        text.undo_block_stop()
        text.tag_add("sel", head, "insert")

    # Make string that displays as n leading blanks.

    def _make_blanks(self, n):
        if self.usetabs:
            ntabs, nspaces = divmod(n, self.tabwidth)
            return '\t' * ntabs + ' ' * nspaces
        else:
            return ' ' * n

    # Delete from beginning of line to insert point, then reinsert
    # column logical (meaning use tabs if appropriate) spaces.

    def reindent_to(self, column):
        text = self.text
        text.undo_block_start()
        text.delete("insert linestart", "insert")
        if column:
            text.insert("insert", self._make_blanks(column))
        text.undo_block_stop()

    def _asktabwidth(self):
        return tkSimpleDialog.askinteger(
            "Tab width",
            "Spaces per tab?",
            parent=self.text,
            initialvalue=self.tabwidth,
            minvalue=1,
            maxvalue=16) or self.tabwidth

    # Guess indentwidth from text content.
    # Return guessed indentwidth.  This should not be believed unless
    # it's in a reasonable range (e.g., it will be 0 if no indented
    # blocks are found).

    def guess_indent(self):
        opener, indented = IndentSearcher(self.text, self.tabwidth).run()
        if opener and indented:
            raw, indentsmall = classifyws(opener, self.tabwidth)
            raw, indentlarge = classifyws(indented, self.tabwidth)
        else:
            indentsmall = indentlarge = 0
        return indentlarge - indentsmall

# "line.col" -> line, as an int
def index2line(index):
    return int(float(index))

# Look at the leading whitespace in s.
# Return pair (# of leading ws characters,
#              effective # of leading blanks after expanding
#              tabs to width tabwidth)

def classifyws(s, tabwidth):
    raw = effective = 0
    for ch in s:
        if ch == ' ':
            raw = raw + 1
            effective = effective + 1
        elif ch == '\t':
            raw = raw + 1
            effective = (effective / tabwidth + 1) * tabwidth
        else:
            break
    return raw, effective

class LineStudier:

    # set to false by self.study(); the other vars retain default values
    # until then
    needstudying = 1

    # line ends with an unescaped backslash not in string or comment?
    backslash_continued = 0

    # line ends with an unterminated string?
    string_continued = 0

    # the last "interesting" character on a line: the last non-ws char
    # before an optional trailing comment; if backslash_continued, lastch
    # precedes the final backslash; if string_continued, the required
    # string-closer (", """, ', ''')
    lastch = ""

    # index of rightmost unmatched ([{ not in a string or comment
    lastopenbrackpos = -1

    import re
    _is_block_closer_re = re.compile(r"""
        \s*
        ( return
        | break
        | continue
        | raise
        | pass
        )
        \b
    """, re.VERBOSE).match

    # colon followed by optional comment
    _looks_like_opener_re = re.compile(r":\s*(#.*)?$").search
    del re


    def __init__(self, line):
        if line[-1:] == '\n':
            line = line[:-1]
        self.line = line
        self.stack = []

    def is_continued(self):
        return self.is_block_opener() or \
               self.is_backslash_continued() or \
               self.is_bracket_continued() or \
               self.is_string_continued()

    def is_block_opener(self):
        if not self._looks_like_opener_re(self.line):
            return 0
        # Looks like an opener, but possible we're in a comment
        #     x = 3 # and then:
        # or a string
        #     x = ":#"
        # If no comment character, we're not in a comment <duh>, and the
        # colon is the last non-ws char on the line so it's not in a
        # (single-line) string either.
        if string.find(self.line, '#') < 0:
            return 1
        self.study()
        return self.lastch == ":"

    def is_backslash_continued(self):
        self.study()
        return self.backslash_continued

    def is_bracket_continued(self):
        self.study()
        return self.lastopenbrackpos >= 0

    def is_string_continued(self):
        self.study()
        return self.string_continued

    def is_block_closer(self):
        return self._is_block_closer_re(self.line)

    def last_open_bracket_index(self):
        assert self.stack
        return self.lastopenbrackpos

    def study(self):
        if not self.needstudying:
            return
        self.needstudying = 0
        line = self.line
        i, n = 0, len(line)
        while i < n:
            ch = line[i]
            if ch == '\\':
                i = i+1
                if i == n:
                    self.backslash_continued = 1
                else:
                    self.lastch = ch + line[i]
                    i = i+1

            elif ch in "\"'":
                # consume string
                w = 1   # width of string quote
                if line[i:i+3] in ('"""', "'''"):
                    w = 3
                    ch = ch * 3
                i = i+w
                self.lastch = ch
                while i < n:
                    if line[i] == '\\':
                        i = i+2
                    elif line[i:i+w] == ch:
                        i = i+w
                        break
                    else:
                        i = i+1
                else:
                    self.string_continued = 1

            elif ch == '#':
                break

            else:
                if ch not in string.whitespace:
                    self.lastch = ch
                    if ch in "([(":
                        self.stack.append(i)
                    elif ch in ")]}" and self.stack:
                        if line[self.stack[-1]] + ch in ("()", "[]", "{}"):
                            del self.stack[-1]
                i = i+1
        # end while i < n:

        if self.stack:
            self.lastopenbrackpos = self.stack[-1]

import tokenize
_tokenize = tokenize
del tokenize

class IndentSearcher:

    # .run() chews over the Text widget, looking for a block opener
    # and the stmt following it.  Returns a pair,
    #     (line containing block opener, line containing stmt)
    # Either or both may be None.

    def __init__(self, text, tabwidth):
        self.text = text
        self.tabwidth = tabwidth
        self.i = self.finished = 0
        self.blkopenline = self.indentedline = None

    def readline(self):
        if self.finished:
            return ""
        i = self.i = self.i + 1
        mark = `i` + ".0"
        if self.text.compare(mark, ">=", "end"):
            return ""
        return self.text.get(mark, mark + " lineend+1c")

    def tokeneater(self, type, token, start, end, line,
                   INDENT=_tokenize.INDENT,
                   NAME=_tokenize.NAME,
                   OPENERS=('class', 'def', 'for', 'if', 'try', 'while')):
        if self.finished:
            pass
        elif type == NAME and token in OPENERS:
            self.blkopenline = line
        elif type == INDENT and self.blkopenline:
            self.indentedline = line
            self.finished = 1

    def run(self):
        save_tabsize = _tokenize.tabsize
        _tokenize.tabsize = self.tabwidth
        try:
            try:
                _tokenize.tokenize(self.readline, self.tokeneater)
            except _tokenize.TokenError:
                # since we cut off the tokenizer early, we can trigger
                # spurious errors
                pass
        finally:
            _tokenize.tabsize = save_tabsize
        return self.blkopenline, self.indentedline
