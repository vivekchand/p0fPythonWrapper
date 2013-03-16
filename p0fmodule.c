#include<Python.h>

// Define a new exception object for our module
static PyObject *p0fmodError;

static PyObject* p0fmod_li(PyObject *self,PyObject *args){
	const char** msg;
	int sts=0;

	// We expect at least 1 string argument to this function
	if(!PyArg_ParseTuple(args,"s",&msg)){
		return NULL; // return error if none found
	}

	list_interfaces();
	sts = 0;
	return Py_BuildValue("i",sts);
}


static PyMethodDef p0fmod_methods[] = {
	//"PythonName"    C-function Name, argument presentation, description
	{"li", 	  p0fmod_li,	METH_VARARGS,	"Say hello from C & print message"},
	{NULL , NULL , 0 , NULL}	/* Sentinel */
};

	
PyMODINIT_FUNC initp0fmod(void) {
	printf("Hello");
	PyObject *m;
	m = Py_InitModule("p0fmod",p0fmod_methods);

	if(m==NULL)	
		return;

}
