/* Method object interface */

extern typeobject Methodtype;

#define is_methodobject(op) ((op)->ob_type == &Methodtype)

typedef object *(*method) FPROTO((object *, object *));

extern object *newmethodobject PROTO((char *, method, object *));
extern method getmethod PROTO((object *));
extern object *getself PROTO((object *));
