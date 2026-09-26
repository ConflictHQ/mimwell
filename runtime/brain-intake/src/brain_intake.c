#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "brain_intake.h"

#ifndef BRAIN_PYTHON_PROGRAM
#error "BRAIN_PYTHON_PROGRAM must select the matching Python runtime"
#endif

#define REQUEST_LIMIT (1024U * 1024U)
#define RESPONSE_LIMIT (4U * 1024U * 1024U)
#define TEXT_LIMIT 4096U

static pthread_mutex_t bootstrap_lock = PTHREAD_MUTEX_INITIALIZER;
/* Python and its imported engine remain alive until process exit. */
static PyObject *bridge = NULL;
static char *engine = NULL;

uint32_t brain_intake_abi_version(void) { return 1; }

static int valid_text(const char *text) {
    return text != NULL && text[0] != '\0' && strnlen(text, TEXT_LIMIT + 1) <= TEXT_LIMIT;
}

static int initialize(const char *directory) {
    int status = BRAIN_INTAKE_INITIALIZATION_FAILED;
    pthread_mutex_lock(&bootstrap_lock);
    if (engine != NULL && strcmp(engine, directory) != 0) {
        pthread_mutex_unlock(&bootstrap_lock);
        return BRAIN_INTAKE_ENGINE_MISMATCH;
    }
    const char *runtime_version = Py_GetVersion();
    if (strncmp(runtime_version, PY_VERSION, strlen(PY_VERSION)) != 0
        || (runtime_version[strlen(PY_VERSION)] != ' ' && runtime_version[strlen(PY_VERSION)] != '\0')) {
        pthread_mutex_unlock(&bootstrap_lock);
        return BRAIN_INTAKE_ENGINE_MISMATCH;
    }
    if (!Py_IsInitialized()) {
        PyPreConfig preconfig;
        PyPreConfig_InitIsolatedConfig(&preconfig);
        preconfig.configure_locale = 0; /* Leave the embedding app's locale alone. */
        preconfig.utf8_mode = 1; /* Engine artifacts are UTF-8, including in a C host. */
        PyStatus preinitialized = Py_PreInitialize(&preconfig);
        if (PyStatus_Exception(preinitialized)) {
            pthread_mutex_unlock(&bootstrap_lock);
            return status;
        }
        PyConfig config;
        PyConfig_InitIsolatedConfig(&config);
        config.install_signal_handlers = 0;
        config.write_bytecode = 0;
        PyStatus initialized = PyConfig_SetBytesString(&config, &config.program_name, BRAIN_PYTHON_PROGRAM);
        if (!PyStatus_Exception(initialized)) initialized = Py_InitializeFromConfig(&config);
        PyConfig_Clear(&config);
        if (PyStatus_Exception(initialized)) {
            pthread_mutex_unlock(&bootstrap_lock);
            return status;
        }
        PyEval_SaveThread();
    }
    PyGILState_STATE gil = PyGILState_Ensure();
    if (bridge == NULL) {
        PyObject *path = PyUnicode_DecodeFSDefault(directory);
        PyObject *paths = PySys_GetObject("path"); /* borrowed */
        if (path != NULL && paths != NULL && PyList_Insert(paths, 0, path) == 0) {
            bridge = PyImport_ImportModule("intake_native");
        }
        Py_XDECREF(path);
    }
    if (bridge != NULL) {
        PyObject *verified = PyObject_CallMethod(bridge, "verify_engine", "s", directory);
        if (verified != NULL && PyObject_IsTrue(verified) == 1) {
            if (engine == NULL) engine = strdup(directory);
            status = engine != NULL ? BRAIN_INTAKE_OK : BRAIN_INTAKE_NO_MEMORY;
        } else {
            status = BRAIN_INTAKE_ENGINE_MISMATCH;
        }
        Py_XDECREF(verified);
    }
    /* Never emit a traceback or private host values into a consumer's logs. */
    PyErr_Clear();
    PyGILState_Release(gil);
    pthread_mutex_unlock(&bootstrap_lock);
    return status;
}

static int invoke(const char *method, const char *directory, const char *root,
                  const char *config, const char *actor, const uint8_t *request,
                  size_t request_length, brain_intake_response **out) {
    if (out == NULL) return BRAIN_INTAKE_INVALID_ARGUMENT;
    *out = NULL;
    if (!valid_text(directory) || !valid_text(root) || !valid_text(config) || !valid_text(actor)
        || request == NULL || request_length == 0 || request_length > REQUEST_LIMIT) {
        return BRAIN_INTAKE_INVALID_ARGUMENT;
    }
    int status = initialize(directory);
    if (status != BRAIN_INTAKE_OK) return status;
    /* Allocate output storage before a governed mutation can commit. */
    brain_intake_response *response = calloc(1, sizeof(*response));
    if (response == NULL) return BRAIN_INTAKE_NO_MEMORY;
    response->data = malloc(RESPONSE_LIMIT);
    if (response->data == NULL) {
        free(response);
        return BRAIN_INTAKE_NO_MEMORY;
    }
    PyGILState_STATE gil = PyGILState_Ensure();
    PyObject *result = PyObject_CallMethod(bridge, method, "sssy#", root, config, actor,
                                         request, (Py_ssize_t)request_length);
    char *data = NULL;
    Py_ssize_t length = 0;
    status = BRAIN_INTAKE_UNAVAILABLE;
    if (result != NULL && PyBytes_AsStringAndSize(result, &data, &length) == 0
        && length >= 0 && (size_t)length <= RESPONSE_LIMIT) {
        memcpy(response->data, data, (size_t)length);
        response->length = (size_t)length;
        *out = response;
        status = BRAIN_INTAKE_OK;
    }
    Py_XDECREF(result);
    PyErr_Clear();
    PyGILState_Release(gil);
    if (status != BRAIN_INTAKE_OK) brain_intake_response_free_v1(response);
    return status;
}

int brain_intake_plan_v1(const char *engine_scripts, const char *root,
                        const char *config, const char *actor,
                        const uint8_t *request, size_t length,
                        brain_intake_response **response) {
    return invoke("plan", engine_scripts, root, config, actor, request, length, response);
}

int brain_intake_operate_v1(const char *engine_scripts, const char *root,
                           const char *config, const char *actor,
                           const uint8_t *request, size_t length,
                           brain_intake_response **response) {
    return invoke("operate", engine_scripts, root, config, actor, request, length, response);
}

void brain_intake_response_free_v1(brain_intake_response *response) {
    if (response == NULL) return;
    free(response->data);
    free(response);
}
