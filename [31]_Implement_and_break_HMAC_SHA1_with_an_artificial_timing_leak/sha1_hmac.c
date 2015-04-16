#include "../tools/sha1.h"
#include <Python.h>

const char secret[] = "Elvis is dead";

/*
 * HMAC generation function to be called from Python
 */
static PyObject* generate_HMAC(PyObject* self, PyObject* args)
{
	size_t i;
	struct sha1nfo s;
	sha1_init(&s);
	sha1_init_Hmac(&s, (const uint8_t*) secret, strlen(secret));


  	uint8_t* array = sha1_result_Hmac(&s);
  	PyObject *lst = PyList_New(SHA1_HASH_LENGTH);
	if (!lst)
	    return NULL;
	for (i = 0; i < SHA1_HASH_LENGTH; i++) {
	    PyObject *num = (PyObject *) PyLong_FromLong(array[i]);
	    if (!num) {
	        Py_DECREF(lst);
	        return NULL;
	    }
	    PyList_SET_ITEM(lst, i, num); 
	}
	return lst;
}

/*
 * Bind Python function names to our C functions
 */
static PyMethodDef sha1_hmac_methods[] = {
  {"generate_HMAC", generate_HMAC, METH_VARARGS, NULL},
  {NULL, NULL,0, NULL}
};

/*
 * Python module definition
 */
static struct PyModuleDef sha1_hmac_module = {
	PyModuleDef_HEAD_INIT,
  	"sha1_hmac",
  	NULL,
  	-1,
  	sha1_hmac_methods
};


/*
 * Python calls this to let us initialize our module
 */
PyMODINIT_FUNC PyInit_sha1_hmac()
{
  (void) PyModule_Create(&sha1_hmac_module);
}

