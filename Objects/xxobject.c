/* Xx objects */

typedef struct {
	OB_HEAD
	object	*x_attr;	/* Attributes dictionary */
} xxobject;

extern typeobject Xxtype;	/* Really static, forward */

static xxobject *
newxxobject(arg)
	object *arg;
{
	textobject *xp;
	xp = NEWOBJ(xxobject, &Xxtype);
	if (xp == NULL)
		return NULL;
	xp->x_attr = NULL;
	return xp;
}

/* Xx methods */

static void
xx_dealloc(xp)
	xxobject *xp;
{
	if (xp->x_attr != NULL)
		DECREF(xp->x_attr);
	DEL(xp);
}

static object *
xx_demo(self, args)
	xxobject *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	INCREF(None);
	return None;
}

static struct methodlist xx_methods[] = {
	"demo",		xx_demo,
	{NULL,		NULL}		/* sentinel */
};

static object *
xx_getattr(xp, name)
	xxobject *xp;
	char *name;
{
	if (xp->x_attr != NULL) {
		object *v = dictlookup(xp->x_attr, name);
		if (v != NULL) {
			INCREF(v);
			return v;
		}
	}
	return findmethod(xx_methods, (object *)xp, name);
}

static int
xx_setattr(xp, name, v)
	xxobject *xp;
	char *name;
	object *v;
{
	if (xp->x_attr == NULL) {
		xp->x_attr = newdictobject();
		if (xp->x_attr == NULL)
			return errno;
	}
	if (v == NULL)
		return dictremove(xp->x_attr, name);
	else
		return dictinsert(xp->x_attr, name, v);
}

static typeobject Xxtype = {
	OB_HEAD_INIT(&Typetype)
	0,			/*ob_size*/
	"xx",			/*tp_name*/
	sizeof(xxobject),	/*tp_size*/
	0,			/*tp_itemsize*/
	/* methods */
	xx_dealloc,	/*tp_dealloc*/
	0,		/*tp_print*/
	xx_getattr,	/*tp_getattr*/
	xx_setattr,	/*tp_setattr*/
	0,		/*tp_compare*/
	0,		/*tp_repr*/
};
