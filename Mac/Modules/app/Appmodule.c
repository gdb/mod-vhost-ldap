
/* =========================== Module App =========================== */

#include "Python.h"



#define SystemSevenOrLater 1

#include "macglue.h"
#include <Memory.h>
#include <Dialogs.h>
#include <Menus.h>
#include <Controls.h>

extern PyObject *ResObj_New(Handle);
extern int ResObj_Convert(PyObject *, Handle *);
extern PyObject *OptResObj_New(Handle);
extern int OptResObj_Convert(PyObject *, Handle *);

extern PyObject *WinObj_New(WindowPtr);
extern int WinObj_Convert(PyObject *, WindowPtr *);
extern PyTypeObject Window_Type;
#define WinObj_Check(x) ((x)->ob_type == &Window_Type)

extern PyObject *DlgObj_New(DialogPtr);
extern int DlgObj_Convert(PyObject *, DialogPtr *);
extern PyTypeObject Dialog_Type;
#define DlgObj_Check(x) ((x)->ob_type == &Dialog_Type)

extern PyObject *MenuObj_New(MenuHandle);
extern int MenuObj_Convert(PyObject *, MenuHandle *);

extern PyObject *CtlObj_New(ControlHandle);
extern int CtlObj_Convert(PyObject *, ControlHandle *);

extern PyObject *GrafObj_New(GrafPtr);
extern int GrafObj_Convert(PyObject *, GrafPtr *);

extern PyObject *BMObj_New(BitMapPtr);
extern int BMObj_Convert(PyObject *, BitMapPtr *);

extern PyObject *WinObj_WhichWindow(WindowPtr);

#include <Appearance.h>

#define resNotFound -192 /* Can't include <Errors.h> because of Python's "errors.h" */

static PyObject *App_Error;

static PyObject *App_RegisterAppearanceClient(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = RegisterAppearanceClient();
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_UnregisterAppearanceClient(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = UnregisterAppearanceClient();
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_SetThemePen(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeBrush inBrush;
	SInt16 inDepth;
	Boolean inIsColorDevice;
	if (!PyArg_ParseTuple(_args, "hhb",
	                      &inBrush,
	                      &inDepth,
	                      &inIsColorDevice))
		return NULL;
	_err = SetThemePen(inBrush,
	                   inDepth,
	                   inIsColorDevice);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_SetThemeBackground(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeBrush inBrush;
	SInt16 inDepth;
	Boolean inIsColorDevice;
	if (!PyArg_ParseTuple(_args, "hhb",
	                      &inBrush,
	                      &inDepth,
	                      &inIsColorDevice))
		return NULL;
	_err = SetThemeBackground(inBrush,
	                          inDepth,
	                          inIsColorDevice);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_SetThemeTextColor(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeTextColor inColor;
	SInt16 inDepth;
	Boolean inIsColorDevice;
	if (!PyArg_ParseTuple(_args, "hhb",
	                      &inColor,
	                      &inDepth,
	                      &inIsColorDevice))
		return NULL;
	_err = SetThemeTextColor(inColor,
	                         inDepth,
	                         inIsColorDevice);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_SetThemeWindowBackground(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	WindowPtr inWindow;
	ThemeBrush inBrush;
	Boolean inUpdate;
	if (!PyArg_ParseTuple(_args, "O&hb",
	                      WinObj_Convert, &inWindow,
	                      &inBrush,
	                      &inUpdate))
		return NULL;
	_err = SetThemeWindowBackground(inWindow,
	                                inBrush,
	                                inUpdate);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeWindowHeader(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemeWindowHeader(&inRect,
	                             inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeWindowListViewHeader(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemeWindowListViewHeader(&inRect,
	                                     inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemePlacard(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemePlacard(&inRect,
	                        inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeEditTextFrame(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemeEditTextFrame(&inRect,
	                              inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeListBoxFrame(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemeListBoxFrame(&inRect,
	                             inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeFocusRect(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	Boolean inHasFocus;
	if (!PyArg_ParseTuple(_args, "O&b",
	                      PyMac_GetRect, &inRect,
	                      &inHasFocus))
		return NULL;
	_err = DrawThemeFocusRect(&inRect,
	                          inHasFocus);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemePrimaryGroup(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemePrimaryGroup(&inRect,
	                             inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeSecondaryGroup(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemeSecondaryGroup(&inRect,
	                               inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeSeparator(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemeSeparator(&inRect,
	                          inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeModelessDialogFrame(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemeModelessDialogFrame(&inRect,
	                                    inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeGenericWell(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	Boolean inFillCenter;
	if (!PyArg_ParseTuple(_args, "O&lb",
	                      PyMac_GetRect, &inRect,
	                      &inState,
	                      &inFillCenter))
		return NULL;
	_err = DrawThemeGenericWell(&inRect,
	                            inState,
	                            inFillCenter);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeFocusRegion(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Boolean inHasFocus;
	if (!PyArg_ParseTuple(_args, "b",
	                      &inHasFocus))
		return NULL;
	_err = DrawThemeFocusRegion((RgnHandle)0,
	                            inHasFocus);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_IsThemeInColor(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	SInt16 inDepth;
	Boolean inIsColorDevice;
	if (!PyArg_ParseTuple(_args, "hb",
	                      &inDepth,
	                      &inIsColorDevice))
		return NULL;
	_rv = IsThemeInColor(inDepth,
	                     inIsColorDevice);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *App_GetThemeAccentColors(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	CTabHandle outColors;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetThemeAccentColors(&outColors);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     ResObj_New, outColors);
	return _res;
}

static PyObject *App_DrawThemeMenuBarBackground(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inBounds;
	ThemeMenuBarState inState;
	UInt32 inAttributes;
	if (!PyArg_ParseTuple(_args, "O&hl",
	                      PyMac_GetRect, &inBounds,
	                      &inState,
	                      &inAttributes))
		return NULL;
	_err = DrawThemeMenuBarBackground(&inBounds,
	                                  inState,
	                                  inAttributes);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_GetThemeMenuBarHeight(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	SInt16 outHeight;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetThemeMenuBarHeight(&outHeight);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outHeight);
	return _res;
}

static PyObject *App_DrawThemeMenuBackground(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inMenuRect;
	ThemeMenuType inMenuType;
	if (!PyArg_ParseTuple(_args, "O&h",
	                      PyMac_GetRect, &inMenuRect,
	                      &inMenuType))
		return NULL;
	_err = DrawThemeMenuBackground(&inMenuRect,
	                               inMenuType);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_GetThemeMenuBackgroundRegion(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inMenuRect;
	ThemeMenuType menuType;
	if (!PyArg_ParseTuple(_args, "O&h",
	                      PyMac_GetRect, &inMenuRect,
	                      &menuType))
		return NULL;
	_err = GetThemeMenuBackgroundRegion(&inMenuRect,
	                                    menuType,
	                                    (RgnHandle)0);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeMenuSeparator(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inItemRect;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetRect, &inItemRect))
		return NULL;
	_err = DrawThemeMenuSeparator(&inItemRect);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_GetThemeMenuSeparatorHeight(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	SInt16 outHeight;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetThemeMenuSeparatorHeight(&outHeight);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outHeight);
	return _res;
}

static PyObject *App_GetThemeMenuItemExtra(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeMenuItemType inItemType;
	SInt16 outHeight;
	SInt16 outWidth;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItemType))
		return NULL;
	_err = GetThemeMenuItemExtra(inItemType,
	                             &outHeight,
	                             &outWidth);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("hh",
	                     outHeight,
	                     outWidth);
	return _res;
}

static PyObject *App_GetThemeMenuTitleExtra(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	SInt16 outWidth;
	Boolean inIsSquished;
	if (!PyArg_ParseTuple(_args, "b",
	                      &inIsSquished))
		return NULL;
	_err = GetThemeMenuTitleExtra(&outWidth,
	                              inIsSquished);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outWidth);
	return _res;
}

static PyObject *App_DrawThemeTabPane(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeDrawState inState;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &inRect,
	                      &inState))
		return NULL;
	_err = DrawThemeTabPane(&inRect,
	                        inState);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_GetThemeTabRegion(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect inRect;
	ThemeTabStyle inStyle;
	ThemeTabDirection inDirection;
	if (!PyArg_ParseTuple(_args, "O&hh",
	                      PyMac_GetRect, &inRect,
	                      &inStyle,
	                      &inDirection))
		return NULL;
	_err = GetThemeTabRegion(&inRect,
	                         inStyle,
	                         inDirection,
	                         (RgnHandle)0);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_SetThemeCursor(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeCursor inCursor;
	if (!PyArg_ParseTuple(_args, "l",
	                      &inCursor))
		return NULL;
	_err = SetThemeCursor(inCursor);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_SetAnimatedThemeCursor(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeCursor inCursor;
	UInt32 inAnimationStep;
	if (!PyArg_ParseTuple(_args, "ll",
	                      &inCursor,
	                      &inAnimationStep))
		return NULL;
	_err = SetAnimatedThemeCursor(inCursor,
	                              inAnimationStep);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_GetThemeScrollBarThumbStyle(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeScrollBarThumbStyle outStyle;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetThemeScrollBarThumbStyle(&outStyle);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outStyle);
	return _res;
}

static PyObject *App_GetThemeScrollBarArrowStyle(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeScrollBarArrowStyle outStyle;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetThemeScrollBarArrowStyle(&outStyle);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outStyle);
	return _res;
}

static PyObject *App_GetThemeCheckBoxStyle(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeCheckBoxStyle outStyle;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetThemeCheckBoxStyle(&outStyle);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outStyle);
	return _res;
}

static PyObject *App_UseThemeFont(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeFontID inFontID;
	ScriptCode inScript;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &inFontID,
	                      &inScript))
		return NULL;
	_err = UseThemeFont(inFontID,
	                    inScript);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeScrollBarArrows(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect bounds;
	ThemeTrackEnableState enableState;
	ThemeTrackPressState pressState;
	Boolean isHoriz;
	Rect trackBounds;
	if (!PyArg_ParseTuple(_args, "O&bbb",
	                      PyMac_GetRect, &bounds,
	                      &enableState,
	                      &pressState,
	                      &isHoriz))
		return NULL;
	_err = DrawThemeScrollBarArrows(&bounds,
	                                enableState,
	                                pressState,
	                                isHoriz,
	                                &trackBounds);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     PyMac_BuildRect, &trackBounds);
	return _res;
}

static PyObject *App_GetThemeScrollBarTrackRect(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect bounds;
	ThemeTrackEnableState enableState;
	ThemeTrackPressState pressState;
	Boolean isHoriz;
	Rect trackBounds;
	if (!PyArg_ParseTuple(_args, "O&bbb",
	                      PyMac_GetRect, &bounds,
	                      &enableState,
	                      &pressState,
	                      &isHoriz))
		return NULL;
	_err = GetThemeScrollBarTrackRect(&bounds,
	                                  enableState,
	                                  pressState,
	                                  isHoriz,
	                                  &trackBounds);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     PyMac_BuildRect, &trackBounds);
	return _res;
}

static PyObject *App_HitTestThemeScrollBarArrows(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	Rect scrollBarBounds;
	ThemeTrackEnableState enableState;
	ThemeTrackPressState pressState;
	Boolean isHoriz;
	Point ptHit;
	Rect trackBounds;
	ControlPartCode partcode;
	if (!PyArg_ParseTuple(_args, "O&bbbO&",
	                      PyMac_GetRect, &scrollBarBounds,
	                      &enableState,
	                      &pressState,
	                      &isHoriz,
	                      PyMac_GetPoint, &ptHit))
		return NULL;
	_rv = HitTestThemeScrollBarArrows(&scrollBarBounds,
	                                  enableState,
	                                  pressState,
	                                  isHoriz,
	                                  ptHit,
	                                  &trackBounds,
	                                  &partcode);
	_res = Py_BuildValue("bO&h",
	                     _rv,
	                     PyMac_BuildRect, &trackBounds,
	                     partcode);
	return _res;
}

static PyObject *App_DrawThemeScrollBarDelimiters(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeWindowType flavor;
	Rect inContRect;
	ThemeDrawState state;
	ThemeWindowAttributes attributes;
	if (!PyArg_ParseTuple(_args, "hO&ll",
	                      &flavor,
	                      PyMac_GetRect, &inContRect,
	                      &state,
	                      &attributes))
		return NULL;
	_err = DrawThemeScrollBarDelimiters(flavor,
	                                    &inContRect,
	                                    state,
	                                    attributes);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_PlayThemeSound(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeSoundKind kind;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetOSType, &kind))
		return NULL;
	_err = PlayThemeSound(kind);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_BeginThemeDragSound(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeDragSoundKind kind;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetOSType, &kind))
		return NULL;
	_err = BeginThemeDragSound(kind);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_EndThemeDragSound(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = EndThemeDragSound();
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeTickMark(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Rect bounds;
	ThemeDrawState state;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      PyMac_GetRect, &bounds,
	                      &state))
		return NULL;
	_err = DrawThemeTickMark(&bounds,
	                         state);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeStandaloneGrowBox(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Point origin;
	ThemeGrowDirection growDirection;
	Boolean isSmall;
	ThemeDrawState state;
	if (!PyArg_ParseTuple(_args, "O&hbl",
	                      PyMac_GetPoint, &origin,
	                      &growDirection,
	                      &isSmall,
	                      &state))
		return NULL;
	_err = DrawThemeStandaloneGrowBox(origin,
	                                  growDirection,
	                                  isSmall,
	                                  state);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_DrawThemeStandaloneNoGrowBox(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Point origin;
	ThemeGrowDirection growDirection;
	Boolean isSmall;
	ThemeDrawState state;
	if (!PyArg_ParseTuple(_args, "O&hbl",
	                      PyMac_GetPoint, &origin,
	                      &growDirection,
	                      &isSmall,
	                      &state))
		return NULL;
	_err = DrawThemeStandaloneNoGrowBox(origin,
	                                    growDirection,
	                                    isSmall,
	                                    state);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_GetThemeStandaloneGrowBoxBounds(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Point origin;
	ThemeGrowDirection growDirection;
	Boolean isSmall;
	Rect bounds;
	if (!PyArg_ParseTuple(_args, "O&hb",
	                      PyMac_GetPoint, &origin,
	                      &growDirection,
	                      &isSmall))
		return NULL;
	_err = GetThemeStandaloneGrowBoxBounds(origin,
	                                       growDirection,
	                                       isSmall,
	                                       &bounds);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     PyMac_BuildRect, &bounds);
	return _res;
}

static PyObject *App_NormalizeThemeDrawingState(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = NormalizeThemeDrawingState();
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_ApplyThemeBackground(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeBackgroundKind inKind;
	Rect bounds;
	ThemeDrawState inState;
	SInt16 inDepth;
	Boolean inColorDev;
	if (!PyArg_ParseTuple(_args, "lO&lhb",
	                      &inKind,
	                      PyMac_GetRect, &bounds,
	                      &inState,
	                      &inDepth,
	                      &inColorDev))
		return NULL;
	_err = ApplyThemeBackground(inKind,
	                            &bounds,
	                            inState,
	                            inDepth,
	                            inColorDev);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_SetThemeTextColorForWindow(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	WindowPtr window;
	Boolean isActive;
	SInt16 depth;
	Boolean isColorDev;
	if (!PyArg_ParseTuple(_args, "O&bhb",
	                      WinObj_Convert, &window,
	                      &isActive,
	                      &depth,
	                      &isColorDev))
		return NULL;
	_err = SetThemeTextColorForWindow(window,
	                                  isActive,
	                                  depth,
	                                  isColorDev);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *App_IsValidAppearanceFileType(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	OSType fileType;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetOSType, &fileType))
		return NULL;
	_rv = IsValidAppearanceFileType(fileType);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *App_GetThemeBrushAsColor(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeBrush inBrush;
	SInt16 inDepth;
	Boolean inColorDev;
	RGBColor outColor;
	if (!PyArg_ParseTuple(_args, "hhb",
	                      &inBrush,
	                      &inDepth,
	                      &inColorDev))
		return NULL;
	_err = GetThemeBrushAsColor(inBrush,
	                            inDepth,
	                            inColorDev,
	                            &outColor);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     QdRGB_New, &outColor);
	return _res;
}

static PyObject *App_GetThemeTextColor(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	ThemeTextColor inColor;
	SInt16 inDepth;
	Boolean inColorDev;
	RGBColor outColor;
	if (!PyArg_ParseTuple(_args, "hhb",
	                      &inColor,
	                      &inDepth,
	                      &inColorDev))
		return NULL;
	_err = GetThemeTextColor(inColor,
	                         inDepth,
	                         inColorDev,
	                         &outColor);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     QdRGB_New, &outColor);
	return _res;
}

static PyMethodDef App_methods[] = {
	{"RegisterAppearanceClient", (PyCFunction)App_RegisterAppearanceClient, 1,
	 "() -> None"},
	{"UnregisterAppearanceClient", (PyCFunction)App_UnregisterAppearanceClient, 1,
	 "() -> None"},
	{"SetThemePen", (PyCFunction)App_SetThemePen, 1,
	 "(ThemeBrush inBrush, SInt16 inDepth, Boolean inIsColorDevice) -> None"},
	{"SetThemeBackground", (PyCFunction)App_SetThemeBackground, 1,
	 "(ThemeBrush inBrush, SInt16 inDepth, Boolean inIsColorDevice) -> None"},
	{"SetThemeTextColor", (PyCFunction)App_SetThemeTextColor, 1,
	 "(ThemeTextColor inColor, SInt16 inDepth, Boolean inIsColorDevice) -> None"},
	{"SetThemeWindowBackground", (PyCFunction)App_SetThemeWindowBackground, 1,
	 "(WindowPtr inWindow, ThemeBrush inBrush, Boolean inUpdate) -> None"},
	{"DrawThemeWindowHeader", (PyCFunction)App_DrawThemeWindowHeader, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemeWindowListViewHeader", (PyCFunction)App_DrawThemeWindowListViewHeader, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemePlacard", (PyCFunction)App_DrawThemePlacard, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemeEditTextFrame", (PyCFunction)App_DrawThemeEditTextFrame, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemeListBoxFrame", (PyCFunction)App_DrawThemeListBoxFrame, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemeFocusRect", (PyCFunction)App_DrawThemeFocusRect, 1,
	 "(Rect inRect, Boolean inHasFocus) -> None"},
	{"DrawThemePrimaryGroup", (PyCFunction)App_DrawThemePrimaryGroup, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemeSecondaryGroup", (PyCFunction)App_DrawThemeSecondaryGroup, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemeSeparator", (PyCFunction)App_DrawThemeSeparator, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemeModelessDialogFrame", (PyCFunction)App_DrawThemeModelessDialogFrame, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"DrawThemeGenericWell", (PyCFunction)App_DrawThemeGenericWell, 1,
	 "(Rect inRect, ThemeDrawState inState, Boolean inFillCenter) -> None"},
	{"DrawThemeFocusRegion", (PyCFunction)App_DrawThemeFocusRegion, 1,
	 "(Boolean inHasFocus) -> None"},
	{"IsThemeInColor", (PyCFunction)App_IsThemeInColor, 1,
	 "(SInt16 inDepth, Boolean inIsColorDevice) -> (Boolean _rv)"},
	{"GetThemeAccentColors", (PyCFunction)App_GetThemeAccentColors, 1,
	 "() -> (CTabHandle outColors)"},
	{"DrawThemeMenuBarBackground", (PyCFunction)App_DrawThemeMenuBarBackground, 1,
	 "(Rect inBounds, ThemeMenuBarState inState, UInt32 inAttributes) -> None"},
	{"GetThemeMenuBarHeight", (PyCFunction)App_GetThemeMenuBarHeight, 1,
	 "() -> (SInt16 outHeight)"},
	{"DrawThemeMenuBackground", (PyCFunction)App_DrawThemeMenuBackground, 1,
	 "(Rect inMenuRect, ThemeMenuType inMenuType) -> None"},
	{"GetThemeMenuBackgroundRegion", (PyCFunction)App_GetThemeMenuBackgroundRegion, 1,
	 "(Rect inMenuRect, ThemeMenuType menuType) -> None"},
	{"DrawThemeMenuSeparator", (PyCFunction)App_DrawThemeMenuSeparator, 1,
	 "(Rect inItemRect) -> None"},
	{"GetThemeMenuSeparatorHeight", (PyCFunction)App_GetThemeMenuSeparatorHeight, 1,
	 "() -> (SInt16 outHeight)"},
	{"GetThemeMenuItemExtra", (PyCFunction)App_GetThemeMenuItemExtra, 1,
	 "(ThemeMenuItemType inItemType) -> (SInt16 outHeight, SInt16 outWidth)"},
	{"GetThemeMenuTitleExtra", (PyCFunction)App_GetThemeMenuTitleExtra, 1,
	 "(Boolean inIsSquished) -> (SInt16 outWidth)"},
	{"DrawThemeTabPane", (PyCFunction)App_DrawThemeTabPane, 1,
	 "(Rect inRect, ThemeDrawState inState) -> None"},
	{"GetThemeTabRegion", (PyCFunction)App_GetThemeTabRegion, 1,
	 "(Rect inRect, ThemeTabStyle inStyle, ThemeTabDirection inDirection) -> None"},
	{"SetThemeCursor", (PyCFunction)App_SetThemeCursor, 1,
	 "(ThemeCursor inCursor) -> None"},
	{"SetAnimatedThemeCursor", (PyCFunction)App_SetAnimatedThemeCursor, 1,
	 "(ThemeCursor inCursor, UInt32 inAnimationStep) -> None"},
	{"GetThemeScrollBarThumbStyle", (PyCFunction)App_GetThemeScrollBarThumbStyle, 1,
	 "() -> (ThemeScrollBarThumbStyle outStyle)"},
	{"GetThemeScrollBarArrowStyle", (PyCFunction)App_GetThemeScrollBarArrowStyle, 1,
	 "() -> (ThemeScrollBarArrowStyle outStyle)"},
	{"GetThemeCheckBoxStyle", (PyCFunction)App_GetThemeCheckBoxStyle, 1,
	 "() -> (ThemeCheckBoxStyle outStyle)"},
	{"UseThemeFont", (PyCFunction)App_UseThemeFont, 1,
	 "(ThemeFontID inFontID, ScriptCode inScript) -> None"},
	{"DrawThemeScrollBarArrows", (PyCFunction)App_DrawThemeScrollBarArrows, 1,
	 "(Rect bounds, ThemeTrackEnableState enableState, ThemeTrackPressState pressState, Boolean isHoriz) -> (Rect trackBounds)"},
	{"GetThemeScrollBarTrackRect", (PyCFunction)App_GetThemeScrollBarTrackRect, 1,
	 "(Rect bounds, ThemeTrackEnableState enableState, ThemeTrackPressState pressState, Boolean isHoriz) -> (Rect trackBounds)"},
	{"HitTestThemeScrollBarArrows", (PyCFunction)App_HitTestThemeScrollBarArrows, 1,
	 "(Rect scrollBarBounds, ThemeTrackEnableState enableState, ThemeTrackPressState pressState, Boolean isHoriz, Point ptHit) -> (Boolean _rv, Rect trackBounds, ControlPartCode partcode)"},
	{"DrawThemeScrollBarDelimiters", (PyCFunction)App_DrawThemeScrollBarDelimiters, 1,
	 "(ThemeWindowType flavor, Rect inContRect, ThemeDrawState state, ThemeWindowAttributes attributes) -> None"},
	{"PlayThemeSound", (PyCFunction)App_PlayThemeSound, 1,
	 "(ThemeSoundKind kind) -> None"},
	{"BeginThemeDragSound", (PyCFunction)App_BeginThemeDragSound, 1,
	 "(ThemeDragSoundKind kind) -> None"},
	{"EndThemeDragSound", (PyCFunction)App_EndThemeDragSound, 1,
	 "() -> None"},
	{"DrawThemeTickMark", (PyCFunction)App_DrawThemeTickMark, 1,
	 "(Rect bounds, ThemeDrawState state) -> None"},
	{"DrawThemeStandaloneGrowBox", (PyCFunction)App_DrawThemeStandaloneGrowBox, 1,
	 "(Point origin, ThemeGrowDirection growDirection, Boolean isSmall, ThemeDrawState state) -> None"},
	{"DrawThemeStandaloneNoGrowBox", (PyCFunction)App_DrawThemeStandaloneNoGrowBox, 1,
	 "(Point origin, ThemeGrowDirection growDirection, Boolean isSmall, ThemeDrawState state) -> None"},
	{"GetThemeStandaloneGrowBoxBounds", (PyCFunction)App_GetThemeStandaloneGrowBoxBounds, 1,
	 "(Point origin, ThemeGrowDirection growDirection, Boolean isSmall) -> (Rect bounds)"},
	{"NormalizeThemeDrawingState", (PyCFunction)App_NormalizeThemeDrawingState, 1,
	 "() -> None"},
	{"ApplyThemeBackground", (PyCFunction)App_ApplyThemeBackground, 1,
	 "(ThemeBackgroundKind inKind, Rect bounds, ThemeDrawState inState, SInt16 inDepth, Boolean inColorDev) -> None"},
	{"SetThemeTextColorForWindow", (PyCFunction)App_SetThemeTextColorForWindow, 1,
	 "(WindowPtr window, Boolean isActive, SInt16 depth, Boolean isColorDev) -> None"},
	{"IsValidAppearanceFileType", (PyCFunction)App_IsValidAppearanceFileType, 1,
	 "(OSType fileType) -> (Boolean _rv)"},
	{"GetThemeBrushAsColor", (PyCFunction)App_GetThemeBrushAsColor, 1,
	 "(ThemeBrush inBrush, SInt16 inDepth, Boolean inColorDev) -> (RGBColor outColor)"},
	{"GetThemeTextColor", (PyCFunction)App_GetThemeTextColor, 1,
	 "(ThemeTextColor inColor, SInt16 inDepth, Boolean inColorDev) -> (RGBColor outColor)"},
	{NULL, NULL, 0}
};




void initApp()
{
	PyObject *m;
	PyObject *d;




	m = Py_InitModule("App", App_methods);
	d = PyModule_GetDict(m);
	App_Error = PyMac_GetOSErrException();
	if (App_Error == NULL ||
	    PyDict_SetItemString(d, "Error", App_Error) != 0)
		Py_FatalError("can't initialize App.Error");
}

/* ========================= End module App ========================= */

