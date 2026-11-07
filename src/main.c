// permwatch — Endpoint Security tabanlı izin/kalıcılık denetleyicisi (CLI çekirdeği)
//
// Abone olunan olaylar:
//   NOTIFY_EXEC                     süreç başlatma (+ DYLD_* ortam değişkeni tespiti)
//   NOTIFY_BTM_LAUNCH_ITEM_ADD      yeni login item / LaunchAgent / LaunchDaemon (macOS 13+)
//   NOTIFY_BTM_LAUNCH_ITEM_REMOVE   kalıcılık öğesinin silinmesi (macOS 13+)
//   NOTIFY_DELETEEXTATTR            yalnızca com.apple.quarantine silinmesi (Gatekeeper atlatma)
//   NOTIFY_GATEKEEPER_USER_OVERRIDE kullanıcı "yine de aç" dedi (macOS 15+)
//   NOTIFY_TCC_MODIFY               TCC izni verildi/geri alındı/değişti (macOS 15.4+)
//
// Çıktı: stdout'a JSON Lines (her satır bir olay).
//
// Kullanım: sudo ./permwatch [-a]
//   -a: tüm Apple platform binary EXEC'lerini göster (varsayılan: yalnızca LOLBin listesi)

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "json.h"

// xnu kern/cs_blobs.h (userland SDK'da yok)
#ifndef CS_VALID
#define CS_VALID 0x00000001
#endif
#ifndef CS_ADHOC
#define CS_ADHOC 0x00000002
#endif

static es_client_t *g_client = NULL;
static bool g_show_platform = false;

// Saldırganların sık kullandığı Apple binary'leri ("living off the land").
// Platform binary filtresi bunları asla gizlemez.
static const char *const k_lolbins[] = {
    "/usr/bin/osascript", "/usr/bin/curl",     "/bin/sh",
    "/bin/bash",          "/bin/zsh",          "/bin/launchctl",
    "/usr/bin/security",  "/usr/bin/xattr",    "/usr/bin/sqlite3",
    "/usr/bin/python3",   "/usr/bin/base64",   "/usr/bin/openssl",
    "/usr/sbin/spctl",    "/usr/bin/codesign", "/usr/bin/nc",
    "/usr/bin/ditto",     "/usr/bin/hdiutil",  "/usr/bin/tccutil",
    NULL,
};

static bool tok_eq(es_string_token_t t, const char *s) {
    size_t n = strlen(s);
    return t.data && t.length == n && memcmp(t.data, s, n) == 0;
}

static bool tok_has_prefix(es_string_token_t t, const char *p) {
    size_t n = strlen(p);
    return t.data && t.length >= n && memcmp(t.data, p, n) == 0;
}

static bool is_lolbin(es_string_token_t path) {
    for (const char *const *p = k_lolbins; *p; p++)
        if (tok_eq(path, *p)) return true;
    return false;
}

// ---------- JSON yardımcıları (ES tipleri) ----------

static void json_tok(FILE *f, es_string_token_t t) {
    if (t.length == 0 || t.data == NULL) fputs("null", f);
    else json_str_n(f, t.data, t.length);
}

static void json_process(FILE *f, const es_message_t *m, const es_process_t *p) {
    if (!p) { fputs("null", f); return; }
    bool valid = p->codesigning_flags & CS_VALID;
    bool adhoc = p->codesigning_flags & CS_ADHOC;
    const char *sig = !valid ? "unsigned"
                    : adhoc  ? "adhoc"
                    : p->is_platform_binary ? "apple" : "developer";

    fprintf(f, "{\"pid\":%d,\"ppid\":%d,\"uid\":%d",
            audit_token_to_pid(p->audit_token), p->ppid,
            audit_token_to_euid(p->audit_token));
    if (m->version >= 4)
        fprintf(f, ",\"responsible_pid\":%d", audit_token_to_pid(p->responsible_audit_token));
    fputs(",\"path\":", f);
    json_tok(f, p->executable->path);
    fputs(",\"signing_id\":", f);
    json_tok(f, p->signing_id);
    fputs(",\"team_id\":", f);
    json_tok(f, p->team_id);
    fprintf(f, ",\"signature\":\"%s\",\"cs_flags\":\"0x%08x\",\"cdhash\":", sig, p->codesigning_flags);
    if (valid) json_hex(f, p->cdhash, sizeof(p->cdhash));
    else fputs("null", f);
    fputc('}', f);
}

// Süreç bilgisi yoksa en azından audit token'dan PID yaz.
static void json_process_or_token(FILE *f, const es_message_t *m, const es_process_t *p,
                                  const audit_token_t *tok) {
    if (p) json_process(f, m, p);
    else if (tok) fprintf(f, "{\"pid\":%d,\"uid\":%d}", audit_token_to_pid(*tok), audit_token_to_euid(*tok));
    else fputs("null", f);
}

static void json_header(FILE *f, const es_message_t *m, const char *type) {
    fprintf(f, "{\"ts\":%ld.%09ld,\"event\":\"%s\",\"process\":",
            (long)m->time.tv_sec, m->time.tv_nsec, type);
    json_process(f, m, m->process);
}

// ---------- enum -> metin ----------

static const char *btm_type_str(es_btm_item_type_t t) {
    switch (t) {
        case ES_BTM_ITEM_TYPE_USER_ITEM:  return "user_item";
        case ES_BTM_ITEM_TYPE_APP:        return "app";
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM: return "login_item";
        case ES_BTM_ITEM_TYPE_AGENT:      return "agent";
        case ES_BTM_ITEM_TYPE_DAEMON:     return "daemon";
    }
    return "unknown";
}

static const char *tcc_update_str(es_tcc_event_type_t t) {
    switch (t) {
        case ES_TCC_EVENT_TYPE_CREATE: return "create";
        case ES_TCC_EVENT_TYPE_MODIFY: return "modify";
        case ES_TCC_EVENT_TYPE_DELETE: return "delete";
        default:                       return "unknown";
    }
}

static const char *tcc_right_str(es_tcc_authorization_right_t r) {
    switch (r) {
        case ES_TCC_AUTHORIZATION_RIGHT_DENIED:           return "denied";
        case ES_TCC_AUTHORIZATION_RIGHT_UNKNOWN:          return "unknown";
        case ES_TCC_AUTHORIZATION_RIGHT_ALLOWED:          return "allowed";
        case ES_TCC_AUTHORIZATION_RIGHT_LIMITED:          return "limited";
        case ES_TCC_AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED: return "add_modify_added";
        case ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID:      return "session_pid";
        case ES_TCC_AUTHORIZATION_RIGHT_LEARN_MORE:       return "learn_more";
    }
    return "unknown";
}

static const char *tcc_reason_str(es_tcc_authorization_reason_t r) {
    switch (r) {
        case ES_TCC_AUTHORIZATION_REASON_NONE:                    return "none";
        case ES_TCC_AUTHORIZATION_REASON_ERROR:                   return "error";
        case ES_TCC_AUTHORIZATION_REASON_USER_CONSENT:            return "user_consent";
        case ES_TCC_AUTHORIZATION_REASON_USER_SET:                return "user_set";
        case ES_TCC_AUTHORIZATION_REASON_SYSTEM_SET:              return "system_set";
        case ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY:          return "service_policy";
        case ES_TCC_AUTHORIZATION_REASON_MDM_POLICY:              return "mdm_policy";
        case ES_TCC_AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY: return "service_override_policy";
        case ES_TCC_AUTHORIZATION_REASON_MISSING_USAGE_STRING:    return "missing_usage_string";
        case ES_TCC_AUTHORIZATION_REASON_PROMPT_TIMEOUT:          return "prompt_timeout";
        case ES_TCC_AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN:       return "preflight_unknown";
        case ES_TCC_AUTHORIZATION_REASON_ENTITLED:                return "entitled";
        case ES_TCC_AUTHORIZATION_REASON_APP_TYPE_POLICY:         return "app_type_policy";
        case ES_TCC_AUTHORIZATION_REASON_PROMPT_CANCEL:           return "prompt_cancel";
    }
    return "unknown";
}

static const char *tcc_identity_type_str(es_tcc_identity_type_t t) {
    switch (t) {
        case ES_TCC_IDENTITY_TYPE_BUNDLE_ID:               return "bundle_id";
        case ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH:         return "executable_path";
        case ES_TCC_IDENTITY_TYPE_POLICY_ID:               return "policy_id";
        case ES_TCC_IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID: return "file_provider_domain_id";
    }
    return "unknown";
}

// ---------- olay işleyicileri ----------

static void on_exec(const es_message_t *m) {
    const es_event_exec_t *ex = &m->event.exec;
    const es_process_t *t = ex->target;

    // DYLD_* ortam değişkeni var mı (DYLD_INSERT_LIBRARIES = dylib enjeksiyonu)?
    uint32_t envc = es_exec_env_count(ex);
    bool has_dyld = false;
    for (uint32_t i = 0; i < envc && !has_dyld; i++)
        has_dyld = tok_has_prefix(es_exec_env(ex, i), "DYLD_");

    bool lolbin = is_lolbin(t->executable->path);

    // Gürültü filtresi: Apple binary'lerini atla, ama LOLBin'leri ve DYLD_* içerenleri asla.
    if (!g_show_platform && t->is_platform_binary && !lolbin && !has_dyld)
        return;

    FILE *f = stdout;
    json_header(f, m, "exec");
    fputs(",\"target\":", f);
    json_process(f, m, t);

    uint32_t argc = es_exec_arg_count(ex);
    fputs(",\"argv\":[", f);
    for (uint32_t i = 0; i < argc && i < 32; i++) {
        if (i) fputc(',', f);
        json_tok(f, es_exec_arg(ex, i));
    }
    fputc(']', f);
    if (argc > 32) fprintf(f, ",\"argc\":%u", argc);

    if (has_dyld) {
        fputs(",\"dyld_env\":[", f);
        bool first = true;
        for (uint32_t i = 0; i < envc; i++) {
            es_string_token_t e = es_exec_env(ex, i);
            if (!tok_has_prefix(e, "DYLD_")) continue;
            if (!first) fputc(',', f);
            json_tok(f, e);
            first = false;
        }
        fputc(']', f);
    }

    fprintf(f, ",\"lolbin\":%s}\n", lolbin ? "true" : "false");
}

static void json_btm_item(FILE *f, const es_btm_launch_item_t *it) {
    fprintf(f, "{\"type\":\"%s\",\"legacy\":%s,\"managed\":%s,\"uid\":%d,\"url\":",
            btm_type_str(it->item_type), it->legacy ? "true" : "false",
            it->managed ? "true" : "false", it->uid);
    json_tok(f, it->item_url);
    fputs(",\"app_url\":", f);
    json_tok(f, it->app_url);
    fputc('}', f);
}

static void on_btm_add(const es_message_t *m) {
    const es_event_btm_launch_item_add_t *e = m->event.btm_launch_item_add;
    FILE *f = stdout;
    json_header(f, m, "btm_launch_item_add");
    fputs(",\"item\":", f);
    json_btm_item(f, e->item);
    fputs(",\"executable_path\":", f);
    json_tok(f, e->executable_path);
    fputs(",\"instigator\":", f);
    json_process_or_token(f, m, e->instigator, m->version >= 8 ? e->instigator_token : NULL);
    fputs(",\"app\":", f);
    json_process_or_token(f, m, e->app, m->version >= 8 ? e->app_token : NULL);
    fputs("}\n", f);
}

static void on_btm_remove(const es_message_t *m) {
    const es_event_btm_launch_item_remove_t *e = m->event.btm_launch_item_remove;
    FILE *f = stdout;
    json_header(f, m, "btm_launch_item_remove");
    fputs(",\"item\":", f);
    json_btm_item(f, e->item);
    fputs(",\"instigator\":", f);
    json_process_or_token(f, m, e->instigator, m->version >= 8 ? e->instigator_token : NULL);
    fputs(",\"app\":", f);
    json_process_or_token(f, m, e->app, m->version >= 8 ? e->app_token : NULL);
    fputs("}\n", f);
}

// Yalnızca quarantine silme ilgimizi çekiyor (xattr -d com.apple.quarantine).
// Yazdıysa true döner.
static bool on_deleteextattr(const es_message_t *m) {
    const es_event_deleteextattr_t *e = &m->event.deleteextattr;
    if (!tok_eq(e->extattr, "com.apple.quarantine")) return false;
    FILE *f = stdout;
    json_header(f, m, "quarantine_removed");
    fputs(",\"target\":", f);
    json_tok(f, e->target->path);
    fputs("}\n", f);
    return true;
}

static void on_gatekeeper_override(const es_message_t *m) {
    const es_event_gatekeeper_user_override_t *e = m->event.gatekeeper_user_override;
    FILE *f = stdout;
    json_header(f, m, "gatekeeper_user_override");
    fputs(",\"target\":", f);
    if (e->file_type == ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE) json_tok(f, e->file.file->path);
    else json_tok(f, e->file.file_path);
    fputs(",\"sha256\":", f);
    if (e->sha256) json_hex(f, *e->sha256, sizeof(*e->sha256));
    else fputs("null", f);
    fputs(",\"target_signing\":", f);
    if (e->signing_info) {
        fputs("{\"signing_id\":", f);
        json_tok(f, e->signing_info->signing_id);
        fputs(",\"team_id\":", f);
        json_tok(f, e->signing_info->team_id);
        fputs(",\"cdhash\":", f);
        json_hex(f, e->signing_info->cdhash, sizeof(e->signing_info->cdhash));
        fputc('}', f);
    } else {
        fputs("null", f);
    }
    fputs("}\n", f);
}

static void on_tcc_modify(const es_message_t *m) {
    const es_event_tcc_modify_t *e = m->event.tcc_modify;
    FILE *f = stdout;
    json_header(f, m, "tcc_modify");
    fputs(",\"service\":", f);
    json_tok(f, e->service);
    fputs(",\"identity\":", f);
    json_tok(f, e->identity);
    fprintf(f, ",\"identity_type\":\"%s\",\"update\":\"%s\",\"right\":\"%s\",\"reason\":\"%s\"",
            tcc_identity_type_str(e->identity_type), tcc_update_str(e->update_type),
            tcc_right_str(e->right), tcc_reason_str(e->reason));
    // instigator NULL olabilir; instigator_token her zaman var.
    fputs(",\"instigator\":", f);
    json_process_or_token(f, m, e->instigator, &e->instigator_token);
    fputs(",\"responsible\":", f);
    json_process_or_token(f, m, e->responsible, e->responsible_token);
    fputs("}\n", f);
}

static void handle(const es_message_t *m) {
    switch (m->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:                     on_exec(m); break;
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:      on_btm_add(m); break;
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:   on_btm_remove(m); break;
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            if (!on_deleteextattr(m)) return;
            break;
        case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE: on_gatekeeper_override(m); break;
        case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:               on_tcc_modify(m); break;
        default: return;
    }
    fflush(stdout);
}

// ---------- kurulum ----------

static const char *new_client_err(es_new_client_result_t r) {
    switch (r) {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return "entitlement yok (com.apple.developer.endpoint-security.client). "
                   "VM'de SIP kapalıyken ad-hoc imzalı binary ile çalıştır.";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return "TCC izni yok. Terminal'e (veya binary'ye) Full Disk Access ver.";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "root gerekli. sudo ile çalıştır.";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "çok fazla ES istemcisi var.";
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return "geçersiz argüman.";
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return "iç hata.";
        default:
            return "bilinmeyen hata.";
    }
}

static void shutdown_client(void) {
    if (g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
        g_client = NULL;
    }
    fflush(stdout);
    exit(0);
}

// Sinyalleri dispatch kaynağıyla yakala: handler normal bir kuyrukta çalışır,
// async-signal-safe kısıtı yoktur.
static void install_signal_source(int sig) {
    signal(sig, SIG_IGN);
    dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, (uintptr_t)sig, 0,
                                                   dispatch_get_main_queue());
    dispatch_source_set_event_handler(src, ^{ shutdown_client(); });
    dispatch_resume(src);
}

typedef struct {
    es_event_type_t type;
    const char *name;
} event_spec_t;

static const event_spec_t k_events[] = {
    {ES_EVENT_TYPE_NOTIFY_EXEC,                     "EXEC"},
    {ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,      "BTM_LAUNCH_ITEM_ADD (13+)"},
    {ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,   "BTM_LAUNCH_ITEM_REMOVE (13+)"},
    {ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR,            "DELETEEXTATTR (quarantine)"},
    {ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE, "GATEKEEPER_USER_OVERRIDE (15+)"},
    {ES_EVENT_TYPE_NOTIFY_TCC_MODIFY,               "TCC_MODIFY (15.4+)"},
};

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "ah")) != -1) {
        switch (opt) {
            case 'a': g_show_platform = true; break;
            default:
                fprintf(stderr, "kullanım: sudo %s [-a]\n"
                                "  -a  tüm Apple platform binary EXEC'lerini göster\n", argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    es_new_client_result_t r = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        (void)c;
        handle(m);
    });
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client başarısız (%d): %s\n", r, new_client_err(r));
        return 1;
    }

    // Kendi sürecimizin olaylarını sustur.
    char self[4096];
    uint32_t sz = sizeof(self);
    if (_NSGetExecutablePath(self, &sz) == 0)
        es_mute_path(g_client, self, ES_MUTE_PATH_TYPE_LITERAL);

    // Her olaya tek tek abone ol; desteklenmeyenler (eski macOS) atlanır.
    fprintf(stderr, "olaylar:\n");
    size_t ok = 0;
    for (size_t i = 0; i < sizeof(k_events) / sizeof(k_events[0]); i++) {
        es_event_type_t t = k_events[i].type;
        bool sub = es_subscribe(g_client, &t, 1) == ES_RETURN_SUCCESS;
        fprintf(stderr, "  [%s] %s\n", sub ? " ok " : "yok ", k_events[i].name);
        ok += sub;
    }
    if (ok == 0) {
        fprintf(stderr, "hiçbir olaya abone olunamadı\n");
        es_delete_client(g_client);
        return 1;
    }

    install_signal_source(SIGINT);
    install_signal_source(SIGTERM);

    fprintf(stderr, "permwatch çalışıyor (platform EXEC: %s). Ctrl+C ile çık.\n",
            g_show_platform ? "hepsi" : "yalnızca LOLBin");
    dispatch_main();
}
