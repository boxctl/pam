#include <node_api.h>
#include <security/pam_appl.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
  char username[256];
  char password[256];
  char service[64];
  int result;
  napi_async_work work;
  napi_deferred deferred;
} AuthData;

static int conv_func(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *data) {
  AuthData *auth = (AuthData *)data;
  *resp = calloc(num_msg, sizeof(struct pam_response));
  if (!*resp) return PAM_BUF_ERR;
  for (int i = 0; i < num_msg; i++) {
    if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
        msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
      (*resp)[i].resp = strdup(auth->password);
    }
  }
  return PAM_SUCCESS;
}

// src/pam.c (partial replace)
static void execute(napi_env env, void *data) {
  AuthData *auth = (AuthData *)data;
  struct pam_conv conv = { conv_func, auth };
  pam_handle_t *pamh = NULL;
  int ret = pam_start(auth->service, auth->username, &conv, &pamh);
  if (ret == PAM_SUCCESS) ret = pam_authenticate(pamh, PAM_SILENT);
  if (pamh) pam_end(pamh, ret);
  auth->result = ret;
}

// src/pam.c - complete callback
static void complete(napi_env env, napi_status status, void *data) {
  AuthData *auth = (AuthData *)data;
  napi_value val;
  napi_get_boolean(env, auth->result == PAM_SUCCESS, &val);
  napi_resolve_deferred(env, auth->deferred, val);
  napi_delete_async_work(env, auth->work);
  free(auth);
}

static napi_value authenticate(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  napi_get_cb_info(env, info, &argc, args, NULL, NULL);

  AuthData *auth = calloc(1, sizeof(AuthData));
  size_t len;
  napi_get_value_string_utf8(env, args[0], auth->username, sizeof(auth->username), &len);
  napi_get_value_string_utf8(env, args[1], auth->password, sizeof(auth->password), &len);
  if (argc >= 3) {
    napi_get_value_string_utf8(env, args[2], auth->service, sizeof(auth->service), &len);
  } else {
    strncpy(auth->service, "login", sizeof(auth->service));
  }

  napi_value promise;
  napi_create_promise(env, &auth->deferred, &promise);

  napi_value name;
  napi_create_string_utf8(env, "pam_authenticate", NAPI_AUTO_LENGTH, &name);
  napi_create_async_work(env, NULL, name, execute, complete, auth, &auth->work);
  napi_queue_async_work(env, auth->work);

  return promise;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, "authenticate", NAPI_AUTO_LENGTH, authenticate, NULL, &fn);
  napi_set_named_property(env, exports, "authenticate", fn);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
