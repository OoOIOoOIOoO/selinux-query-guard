/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <stdint.h>
#include <stddef.h>
#include <asm/current.h>
#include <common.h>
#include <security/selinux/include/security.h>

KPM_NAME("selinux-query-guard");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("OoO");
KPM_DESCRIPTION("Intercepts and normalizes sensitive SELinux query results");

#define LOG_PREFIX "[kpm/selinux_query_guard] "
#define ARRAY_SIZE_LOCAL(x) (sizeof(x) / sizeof((x)[0]))
#define ERRNO_EINVAL 22
#define SELINUX_ACCESS_QUERY_ALLOWED 0x801000u

typedef int (*security_setprocattr_t)(const char *lsm, const char *name, void *value, size_t size);
typedef int (*security_context_to_sid_t)(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
typedef int (*security_context_str_to_sid_t)(const char *scontext, u32 *out_sid, gfp_t gfp);
typedef int (*security_context_to_sid_force_t)(const char *scontext, u32 scontext_len, u32 *sid);
typedef int (*security_secctx_to_secid_t)(const char *secdata, u32 seclen, u32 *secid);
typedef int (*security_secid_to_secctx_t)(u32 secid, char **secdata, u32 *seclen);
typedef void (*security_compute_av_user_t)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);
typedef void (*security_compute_av_t)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd,
                                      struct extended_perms *xperms);

static security_setprocattr_t sym_security_setprocattr;
static security_context_to_sid_t sym_security_context_to_sid;
static security_context_str_to_sid_t sym_security_context_str_to_sid;
static security_context_to_sid_force_t sym_security_context_to_sid_force;
static security_secctx_to_secid_t sym_security_secctx_to_secid;
static security_secid_to_secctx_t sym_security_secid_to_secctx;
static security_compute_av_user_t sym_security_compute_av_user;
static security_compute_av_t sym_security_compute_av;
static pid_t (*sym_task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns);
static void *sym_selinux_setprocattr;
static void *sym_security_bounded_transition;
static void *sym_security_validate_transition;
static void *sym_security_validate_transition_user;

static bool hooks_installed;
static bool selinux_compat;
static unsigned long av_log_count;
static uid_t learned_probe_uid = (uid_t)-1;
static uid_t learned_probe_isolated_uid = (uid_t)-1;
static pid_t learned_probe_tgid = -1;

struct hook_record
{
    void *addr;
    void *before;
    void *after;
    int argno;
    bool installed;
    const char *name;
};

struct source_info
{
    pid_t pid;
    pid_t tgid;
    uid_t uid;
    uid_t euid;
    uid_t fsuid;
    const char *comm;
    const char *source_class;
    bool is_app_uid;
    bool is_isolated_uid;
    bool is_privileged_uid;
    bool is_root_manager_comm;
    bool is_sniffer;
};

enum proposal_kind
{
    PROPOSAL_NONE = 0,
    PROPOSAL_RET_EINVAL,
    PROPOSAL_AV_DENY,
};

struct audit_proposal
{
    enum proposal_kind kind;
    const char *point;
    const char *reason;
    bool applicable;
    bool would_change;
    long long orig_ret;
    long long proposed_ret;
    u32 orig_allowed;
    u32 proposed_allowed;
};

static const char *interesting_contexts[] = {
    "u:r:app_zygote:s0",
    "u:r:isolated_app:s0",
    "u:r:ksu:s0",
    "u:r:ksu_file:s0",
    "u:r:magisk:s0",
    "u:r:magisk_file:s0",
    "u:r:lsposed_file:s0",
    "u:r:xposed_data:s0",
    "u:r:system_server:s0",
    "u:r:fsck_untrusted:s0",
    "u:r:shell:s0",
    "u:r:su:s0",
    "u:r:adbd:s0",
    "u:r:adbroot:s0",
    "u:r:untrusted_app:s0",
    "u:r:zygote:s0",
    "u:object_r:ksu_file:s0",
    "u:object_r:lsposed_file:s0",
    "u:object_r:xposed_data:s0",
    "u:object_r:adb_data_file:s0",
};

static pid_t current_pid_of(enum pid_type type)
{
    if (sym_task_pid_nr_ns) return sym_task_pid_nr_ns(current, type, 0);
    return -1;
}

static const char *current_comm_safe(void)
{
    const char *comm = get_task_comm(current);
    return comm ? comm : "?";
}

static bool streq_safe(const char *a, const char *b)
{
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

static bool context_has_prefix(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool is_interesting_context(const char *ctx)
{
    size_t i;

    if (!ctx) return false;
    for (i = 0; i < ARRAY_SIZE_LOCAL(interesting_contexts); i++) {
        if (streq_safe(ctx, interesting_contexts[i])) return true;
    }
    return context_has_prefix(ctx, "u:r:ksu")
        || context_has_prefix(ctx, "u:r:magisk")
        || context_has_prefix(ctx, "u:r:lsposed")
        || context_has_prefix(ctx, "u:r:xposed")
        || context_has_prefix(ctx, "u:object_r:ksu")
        || context_has_prefix(ctx, "u:object_r:magisk")
        || context_has_prefix(ctx, "u:object_r:lsposed")
        || context_has_prefix(ctx, "u:object_r:xposed");
}

static unsigned int android_appid(uid_t uid)
{
    return (unsigned int)(uid % 100000);
}

static bool uid_is_android_app(uid_t uid)
{
    unsigned int appid = android_appid(uid);

    return appid >= 10000 && appid <= 19999;
}

static bool uid_is_android_isolated(uid_t uid)
{
    unsigned int appid = android_appid(uid);

    return appid >= 90000 && appid <= 99999;
}

static uid_t current_cred_uid_at(int16_t offset)
{
    struct cred *cred;

    if (task_struct_offset.cred_offset <= 0 || offset <= 0) return (uid_t)-1;
    cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    if (!cred) return (uid_t)-1;
    return *(uid_t *)((uintptr_t)cred + offset);
}

static bool comm_is_root_manager(const char *comm)
{
    if (!comm) return false;
    return strstr(comm, "apatch")
        || strstr(comm, "APatch")
        || strstr(comm, "magisk")
        || strstr(comm, "Magisk")
        || strstr(comm, "kernelsu")
        || strstr(comm, "KernelSU")
        || strstr(comm, "ksud")
        || strstr(comm, "lspd")
        || strstr(comm, "lsposed")
        || strstr(comm, "zygisk")
        || streq_safe(comm, "su")
        || streq_safe(comm, "apd");
}

static bool source_matches_learned_probe(const struct source_info *src)
{
    if (!src) return false;
    if (learned_probe_tgid > 0 && src->tgid == learned_probe_tgid) return true;
    if (learned_probe_uid != (uid_t)-1 && src->uid == learned_probe_uid) return true;
    if (learned_probe_isolated_uid != (uid_t)-1 && src->uid == learned_probe_isolated_uid) return true;
    return false;
}

static const char *classify_source(struct source_info *src, bool sensitive_probe)
{
    if (!src) return "unknown";

    if (src->is_root_manager_comm) return "root-manager";
    if (src->is_privileged_uid) return "privileged/system";

    if (source_matches_learned_probe(src)) {
        src->is_sniffer = true;
        return "sensitive-selinux-prober";
    }

    if (sensitive_probe && (src->is_app_uid || src->is_isolated_uid)) {
        if (src->is_isolated_uid) learned_probe_isolated_uid = src->uid;
        if (src->is_app_uid) learned_probe_uid = src->uid;
        learned_probe_tgid = src->tgid;
        src->is_sniffer = true;
        return "sensitive-selinux-prober";
    }

    if (src->is_app_uid || src->is_isolated_uid) return "ordinary-app";
    return "kernel-or-other";
}

static void fill_source_info(struct source_info *src, bool sensitive_probe)
{
    if (!src) return;
    src->pid = current_pid_of(PIDTYPE_PID);
    src->tgid = current_pid_of(PIDTYPE_TGID);
    src->uid = current_uid();
    src->euid = current_cred_uid_at(cred_offset.euid_offset);
    src->fsuid = current_cred_uid_at(cred_offset.fsuid_offset);
    src->comm = current_comm_safe();
    src->is_app_uid = uid_is_android_app(src->uid);
    src->is_isolated_uid = uid_is_android_isolated(src->uid);
    src->is_privileged_uid = src->uid == 0 || src->euid == 0 || src->uid == 1000 || src->uid == 2000;
    src->is_root_manager_comm = comm_is_root_manager(src->comm);
    src->is_sniffer = false;
    src->source_class = classify_source(src, sensitive_probe);
}

#define SRC_FMT "src=%s pid=%d tgid=%d uid=%u euid=%u fsuid=%u comm=%s"
#define SRC_ARGS(src) (src).source_class, (src).pid, (src).tgid, (unsigned int)(src).uid, \
                      (unsigned int)(src).euid, (unsigned int)(src).fsuid, (src).comm

static long long normalize_ret(uint64_t ret)
{
    int32_t ret32 = (int32_t)(ret & 0xffffffffu);

    if ((ret & 0xffffffff00000000ull) == 0xffffffff00000000ull) return (long long)(int64_t)ret;
    if (ret32 < 0) return (long long)ret32;
    return (long long)ret;
}

static bool source_is_sniffer_like(const struct source_info *src)
{
    if (!src || !src->source_class) return false;
    return streq_safe(src->source_class, "sensitive-selinux-prober");
}

static void init_proposal(struct audit_proposal *p, const char *point)
{
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->kind = PROPOSAL_NONE;
    p->point = point;
    p->reason = "not-applicable";
}

static void build_ret_einval_proposal(struct audit_proposal *p, const char *point, uint64_t raw_ret,
                                      const struct source_info *src, bool sensitive_probe)
{
    long long ret = normalize_ret(raw_ret);

    init_proposal(p, point);
    if (!p) return;
    p->orig_ret = ret;
    p->proposed_ret = -ERRNO_EINVAL;

    if (!source_is_sniffer_like(src)) {
        p->reason = "non-sniffer-source";
        return;
    }
    if (!sensitive_probe) {
        p->reason = "non-sensitive-probe";
        return;
    }

    p->kind = PROPOSAL_RET_EINVAL;
    p->applicable = true;
    p->would_change = ret != p->proposed_ret;
    p->reason = "normalize-sensitive-procattr-result-to-einval";
}

static void build_av_deny_proposal(struct audit_proposal *p, const char *point, const struct av_decision *avd,
                                   const struct source_info *src)
{
    init_proposal(p, point);
    if (!p || !avd) return;
    p->orig_allowed = avd->allowed;
    p->proposed_allowed = 0;

    if (!source_is_sniffer_like(src)) {
        p->reason = "non-sniffer-source";
        return;
    }
    if (avd->allowed == SELINUX_ACCESS_QUERY_ALLOWED) {
        p->reason = "preserve-selinux-access-query-capability";
        return;
    }

    p->kind = PROPOSAL_AV_DENY;
    p->applicable = true;
    p->would_change = avd->allowed != p->proposed_allowed;
    p->reason = "deny-user-selinux-access-query";
}

static bool apply_ret_proposal(hook_fargs0_t *args, const struct audit_proposal *p)
{
    if (!args || !p || !p->applicable || !p->would_change) return false;
    args->ret = (uint64_t)(int64_t)p->proposed_ret;
    return true;
}

static bool apply_av_proposal(struct av_decision *avd, const struct audit_proposal *p)
{
    if (!avd || !p || !p->applicable || !p->would_change) return false;
    avd->allowed = p->proposed_allowed;
    return true;
}

static void log_ret_proposal(const struct audit_proposal *p, const struct source_info *src, bool ret_modified)
{
    if (!p || !p->applicable) return;
    if (src) {
        pr_info(LOG_PREFIX "proposal point=%s kind=ret " SRC_FMT " orig_ret=%lld proposed_ret=%lld final_ret=%lld would_change=%d reason=%s action=%s\n",
                p->point ? p->point : "?", SRC_ARGS((*src)), p->orig_ret, p->proposed_ret,
                ret_modified ? p->proposed_ret : p->orig_ret, p->would_change ? 1 : 0,
                p->reason ? p->reason : "?", ret_modified ? "ret-modified" : "ret-unchanged");
    } else {
        pr_info(LOG_PREFIX "proposal point=%s kind=ret orig_ret=%lld proposed_ret=%lld final_ret=%lld would_change=%d reason=%s action=%s\n",
                p->point ? p->point : "?", p->orig_ret, p->proposed_ret,
                ret_modified ? p->proposed_ret : p->orig_ret, p->would_change ? 1 : 0,
                p->reason ? p->reason : "?", ret_modified ? "ret-modified" : "ret-unchanged");
    }
}

static void log_av_proposal(const struct audit_proposal *p, const struct source_info *src, bool av_modified)
{
    if (!p || !p->applicable) return;
    if (src) {
        pr_info(LOG_PREFIX "proposal point=%s kind=av " SRC_FMT " orig_allowed=0x%x proposed_allowed=0x%x final_allowed=0x%x would_change=%d reason=%s action=%s\n",
                p->point ? p->point : "?", SRC_ARGS((*src)), p->orig_allowed, p->proposed_allowed,
                av_modified ? p->proposed_allowed : p->orig_allowed, p->would_change ? 1 : 0,
                p->reason ? p->reason : "?", av_modified ? "av-modified" : "av-unchanged");
    } else {
        pr_info(LOG_PREFIX "proposal point=%s kind=av orig_allowed=0x%x proposed_allowed=0x%x final_allowed=0x%x would_change=%d reason=%s action=%s\n",
                p->point ? p->point : "?", p->orig_allowed, p->proposed_allowed,
                av_modified ? p->proposed_allowed : p->orig_allowed, p->would_change ? 1 : 0,
                p->reason ? p->reason : "?", av_modified ? "av-modified" : "av-unchanged");
    }
}

static void copy_context(char *dst, size_t dst_len, const char *src, size_t src_len)
{
    size_t n;

    if (!dst || !dst_len) return;
    dst[0] = '\0';
    if (!src) return;
    n = src_len;
    if (!n || n > dst_len - 1) n = dst_len - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool should_log_av(void)
{
    av_log_count++;
    if (av_log_count <= 64) return true;
    return (av_log_count & 0xff) == 0;
}

static bool need_selinux_compat_signature(void)
{
    return kver >= VERSION(4, 17, 0) && kver < VERSION(6, 4, 0);
}

static void after_security_setprocattr(hook_fargs4_t *args, void *udata)
{
    const char *lsm = (const char *)args->arg0;
    const char *name = (const char *)args->arg1;
    const char *value = (const char *)args->arg2;
    size_t size = (size_t)args->arg3;
    char value_buf[128];
    struct source_info src;

    if (!streq_safe(name, "current")) return;
    copy_context(value_buf, sizeof(value_buf), value, size);
    fill_source_info(&src, is_interesting_context(value_buf));

    pr_info(LOG_PREFIX "setprocattr ret=%lld " SRC_FMT " lsm=%s name=%s size=%zu value=%s%s\n",
            (long long)args->ret, SRC_ARGS(src), lsm ? lsm : "(null)",
            name ? name : "(null)", size, value_buf,
            is_interesting_context(value_buf) ? " [interesting]" : "");
}

static void before_selinux_setprocattr(hook_fargs3_t *args, void *udata)
{
    const char *name = (const char *)args->arg0;
    const char *value = (const char *)args->arg1;
    size_t size = (size_t)args->arg2;
    char value_buf[128];
    struct source_info src;

    args->local.data0 = 0;
    args->local.data1 = 0;
    if (!streq_safe(name, "current")) return;
    copy_context(value_buf, sizeof(value_buf), value, size);
    args->local.data0 = is_interesting_context(value_buf) ? 1 : 0;
    args->local.data1 = streq_safe(name, "current") ? 1 : 0;
    fill_source_info(&src, args->local.data0 ? true : false);

    pr_info(LOG_PREFIX "%s enter " SRC_FMT " name=%s size=%zu value=%s%s\n",
            (const char *)udata, SRC_ARGS(src), name ? name : "(null)", size, value_buf,
            args->local.data0 ? " [interesting]" : "");
}

static void after_selinux_setprocattr(hook_fargs3_t *args, void *udata)
{
    struct source_info src;
    struct audit_proposal proposal;

    if (!args->local.data1 && !args->local.data0) return;
    fill_source_info(&src, args->local.data0 ? true : false);
    pr_info(LOG_PREFIX "%s exit ret=%lld " SRC_FMT " current=%llu interesting=%llu\n",
            (const char *)udata, normalize_ret(args->ret), SRC_ARGS(src),
            (unsigned long long)args->local.data1, (unsigned long long)args->local.data0);
    build_ret_einval_proposal(&proposal, "selinux_setprocattr", args->ret, &src,
                              args->local.data0 ? true : false);
    log_ret_proposal(&proposal, &src, apply_ret_proposal((hook_fargs0_t *)args, &proposal));
}

static void before_context_to_sid(hook_fargs4_t *args, void *udata)
{
    const char *ctx = (const char *)args->arg0;
    u32 len = (u32)args->arg1;
    char buf[128];
    struct source_info src;

    copy_context(buf, sizeof(buf), ctx, len);
    args->local.data0 = is_interesting_context(buf) ? 1 : 0;
    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "%s enter " SRC_FMT " len=%u ctx=%s%s\n",
                (const char *)udata, SRC_ARGS(src), len, buf, args->local.data0 ? " [interesting]" : "");
    }
}

static void after_context_to_sid(hook_fargs4_t *args, void *udata)
{
    u32 *out_sid = (u32 *)args->arg2;
    u32 sid = out_sid ? *out_sid : 0;
    struct source_info src;

    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "%s exit ret=%lld sid=%u " SRC_FMT "\n",
                (const char *)udata, (long long)args->ret, sid, SRC_ARGS(src));
    }
}

static void before_context_str_to_sid(hook_fargs3_t *args, void *udata)
{
    const char *ctx = (const char *)args->arg0;
    struct source_info src;

    args->local.data0 = is_interesting_context(ctx) ? 1 : 0;
    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "security_context_str_to_sid enter " SRC_FMT " ctx=%s%s\n",
                SRC_ARGS(src),
                ctx ? ctx : "(null)", args->local.data0 ? " [interesting]" : "");
    }
}

static void after_context_str_to_sid(hook_fargs3_t *args, void *udata)
{
    u32 *out_sid = (u32 *)args->arg1;
    u32 sid = out_sid ? *out_sid : 0;
    struct source_info src;

    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "security_context_str_to_sid exit ret=%lld sid=%u " SRC_FMT "\n",
                (long long)args->ret, sid, SRC_ARGS(src));
    }
}

static void before_context_to_sid_force(hook_fargs4_t *args, void *udata)
{
    before_context_to_sid(args, udata);
}

static void after_context_to_sid_force(hook_fargs4_t *args, void *udata)
{
    u32 *out_sid = (u32 *)args->arg2;
    u32 sid = out_sid ? *out_sid : 0;
    struct source_info src;

    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "%s exit ret=%lld sid=%u " SRC_FMT "\n",
                (const char *)udata, (long long)args->ret, sid, SRC_ARGS(src));
    }
}

static void before_context_to_sid_compat(hook_fargs5_t *args, void *udata)
{
    const char *ctx = (const char *)args->arg1;
    u32 len = (u32)args->arg2;
    char buf[128];
    struct source_info src;

    copy_context(buf, sizeof(buf), ctx, len);
    args->local.data0 = is_interesting_context(buf) ? 1 : 0;
    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "%s compat enter " SRC_FMT " len=%u ctx=%s%s\n",
                (const char *)udata, SRC_ARGS(src), len, buf, args->local.data0 ? " [interesting]" : "");
    }
}

static void after_context_to_sid_compat(hook_fargs5_t *args, void *udata)
{
    u32 *out_sid = (u32 *)args->arg3;
    u32 sid = out_sid ? *out_sid : 0;
    struct source_info src;

    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "%s compat exit ret=%lld sid=%u " SRC_FMT "\n",
                (const char *)udata, (long long)args->ret, sid, SRC_ARGS(src));
    }
}

static void before_context_str_to_sid_compat(hook_fargs4_t *args, void *udata)
{
    const char *ctx = (const char *)args->arg1;
    struct source_info src;

    args->local.data0 = is_interesting_context(ctx) ? 1 : 0;
    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "security_context_str_to_sid compat enter " SRC_FMT " ctx=%s%s\n",
                SRC_ARGS(src),
                ctx ? ctx : "(null)", args->local.data0 ? " [interesting]" : "");
    }
}

static void after_context_str_to_sid_compat(hook_fargs4_t *args, void *udata)
{
    u32 *out_sid = (u32 *)args->arg2;
    u32 sid = out_sid ? *out_sid : 0;
    struct source_info src;

    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "security_context_str_to_sid compat exit ret=%lld sid=%u " SRC_FMT "\n",
                (long long)args->ret, sid, SRC_ARGS(src));
    }
}

static void before_context_to_sid_force_compat(hook_fargs4_t *args, void *udata)
{
    const char *ctx = (const char *)args->arg1;
    u32 len = (u32)args->arg2;
    char buf[128];
    struct source_info src;

    copy_context(buf, sizeof(buf), ctx, len);
    args->local.data0 = is_interesting_context(buf) ? 1 : 0;
    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "%s compat enter " SRC_FMT " len=%u ctx=%s%s\n",
                (const char *)udata, SRC_ARGS(src), len, buf, args->local.data0 ? " [interesting]" : "");
    }
}

static void after_context_to_sid_force_compat(hook_fargs4_t *args, void *udata)
{
    u32 *out_sid = (u32 *)args->arg3;
    u32 sid = out_sid ? *out_sid : 0;
    struct source_info src;

    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "%s compat exit ret=%lld sid=%u " SRC_FMT "\n",
                (const char *)udata, (long long)args->ret, sid, SRC_ARGS(src));
    }
}

static void before_security_secctx_to_secid(hook_fargs3_t *args, void *udata)
{
    const char *ctx = (const char *)args->arg0;
    u32 len = (u32)args->arg1;
    char buf[128];
    struct source_info src;

    copy_context(buf, sizeof(buf), ctx, len);
    args->local.data0 = is_interesting_context(buf) ? 1 : 0;
    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "security_secctx_to_secid enter " SRC_FMT " len=%u ctx=%s%s\n",
                SRC_ARGS(src),
                len, buf, args->local.data0 ? " [interesting]" : "");
    }
}

static void after_security_secctx_to_secid(hook_fargs3_t *args, void *udata)
{
    u32 *secid = (u32 *)args->arg2;
    struct source_info src;

    if (args->local.data0) {
        fill_source_info(&src, args->local.data0 ? true : false);
        pr_info(LOG_PREFIX "security_secctx_to_secid exit ret=%lld secid=%u " SRC_FMT "\n",
                (long long)args->ret, secid ? *secid : 0, SRC_ARGS(src));
    }
}

static void after_security_secid_to_secctx(hook_fargs3_t *args, void *udata)
{
    u32 secid = (u32)args->arg0;
    char **secdata = (char **)args->arg1;
    u32 *seclen = (u32 *)args->arg2;
    char buf[128];
    struct source_info src;

    if (!secdata || !*secdata || !seclen) return;

    copy_context(buf, sizeof(buf), *secdata, *seclen);
    if (is_interesting_context(buf)) {
        fill_source_info(&src, is_interesting_context(buf));
        pr_info(LOG_PREFIX "security_secid_to_secctx exit ret=%lld secid=%u " SRC_FMT " len=%u ctx=%s%s\n",
                (long long)args->ret, secid, SRC_ARGS(src), *seclen, buf,
                is_interesting_context(buf) ? " [interesting]" : "");
    }
}

static void after_security_compute_av_user(hook_fargs4_t *args, void *udata)
{
    struct av_decision *avd = (struct av_decision *)args->arg3;
    struct source_info src;
    struct audit_proposal proposal;
    bool log_call;

    if (!avd) return;
    fill_source_info(&src, false);
    log_call = source_is_sniffer_like(&src) || should_log_av();
    if (log_call) {
        pr_info(LOG_PREFIX "security_compute_av_user " SRC_FMT " ssid=%u tsid=%u class=%u allowed=0x%x auditallow=0x%x auditdeny=0x%x seq=%u flags=0x%x\n",
                SRC_ARGS(src),
                (u32)args->arg0, (u32)args->arg1, (u16)args->arg2, avd->allowed,
                avd->auditallow, avd->auditdeny, avd->seqno, avd->flags);
    }
    build_av_deny_proposal(&proposal, "security_compute_av_user", avd, &src);
    log_av_proposal(&proposal, &src, apply_av_proposal(avd, &proposal));
}

static void after_security_compute_av(hook_fargs5_t *args, void *udata)
{
    struct av_decision *avd = (struct av_decision *)args->arg3;
    struct source_info src;

    if (!should_log_av() || !avd) return;
    fill_source_info(&src, false);
    pr_info(LOG_PREFIX "security_compute_av " SRC_FMT " ssid=%u tsid=%u class=%u allowed=0x%x auditallow=0x%x auditdeny=0x%x seq=%u flags=0x%x\n",
            SRC_ARGS(src),
            (u32)args->arg0, (u32)args->arg1, (u16)args->arg2, avd->allowed,
            avd->auditallow, avd->auditdeny, avd->seqno, avd->flags);
}

static void after_security_compute_av_user_compat(hook_fargs5_t *args, void *udata)
{
    struct av_decision *avd = (struct av_decision *)args->arg4;
    struct source_info src;
    struct audit_proposal proposal;
    bool log_call;

    if (!avd) return;
    fill_source_info(&src, false);
    log_call = source_is_sniffer_like(&src) || should_log_av();
    if (log_call) {
        pr_info(LOG_PREFIX "security_compute_av_user compat " SRC_FMT " ssid=%u tsid=%u class=%u allowed=0x%x auditallow=0x%x auditdeny=0x%x seq=%u flags=0x%x\n",
                SRC_ARGS(src),
                (u32)args->arg1, (u32)args->arg2, (u16)args->arg3, avd->allowed,
                avd->auditallow, avd->auditdeny, avd->seqno, avd->flags);
    }
    build_av_deny_proposal(&proposal, "security_compute_av_user", avd, &src);
    log_av_proposal(&proposal, &src, apply_av_proposal(avd, &proposal));
}

static void after_security_compute_av_compat(hook_fargs6_t *args, void *udata)
{
    struct av_decision *avd = (struct av_decision *)args->arg4;
    struct source_info src;

    if (!should_log_av() || !avd) return;
    fill_source_info(&src, false);
    pr_info(LOG_PREFIX "security_compute_av compat " SRC_FMT " ssid=%u tsid=%u class=%u allowed=0x%x auditallow=0x%x auditdeny=0x%x seq=%u flags=0x%x\n",
            SRC_ARGS(src),
            (u32)args->arg1, (u32)args->arg2, (u16)args->arg3, avd->allowed,
            avd->auditallow, avd->auditdeny, avd->seqno, avd->flags);
}

static void after_security_bounded_transition(hook_fargs2_t *args, void *udata)
{
    struct source_info src;
    struct audit_proposal proposal;

    fill_source_info(&src, true);
    pr_info(LOG_PREFIX "security_bounded_transition ret=%lld " SRC_FMT " oldsid=%u newsid=%u\n",
            normalize_ret(args->ret), SRC_ARGS(src), (u32)args->arg0, (u32)args->arg1);
    build_ret_einval_proposal(&proposal, "security_bounded_transition", args->ret, &src, true);
    log_ret_proposal(&proposal, &src, apply_ret_proposal((hook_fargs0_t *)args, &proposal));
}

static void after_security_bounded_transition_compat(hook_fargs3_t *args, void *udata)
{
    struct source_info src;
    struct audit_proposal proposal;

    fill_source_info(&src, true);
    pr_info(LOG_PREFIX "security_bounded_transition compat ret=%lld " SRC_FMT " oldsid=%u newsid=%u\n",
            normalize_ret(args->ret), SRC_ARGS(src), (u32)args->arg1, (u32)args->arg2);
    build_ret_einval_proposal(&proposal, "security_bounded_transition", args->ret, &src, true);
    log_ret_proposal(&proposal, &src, apply_ret_proposal((hook_fargs0_t *)args, &proposal));
}

static void after_security_validate_transition(hook_fargs4_t *args, void *udata)
{
    struct source_info src;

    if (args->ret == 0) return;
    fill_source_info(&src, true);
    pr_info(LOG_PREFIX "%s ret=%lld " SRC_FMT " oldsid=%u newsid=%u tasksid=%u class=%u\n",
            (const char *)udata, (long long)args->ret, SRC_ARGS(src),
            (u32)args->arg0, (u32)args->arg1, (u32)args->arg2, (u16)args->arg3);
}

static void after_security_validate_transition_compat(hook_fargs5_t *args, void *udata)
{
    struct source_info src;

    if (args->ret == 0) return;
    fill_source_info(&src, true);
    pr_info(LOG_PREFIX "%s compat ret=%lld " SRC_FMT " oldsid=%u newsid=%u tasksid=%u class=%u\n",
            (const char *)udata, (long long)args->ret, SRC_ARGS(src),
            (u32)args->arg1, (u32)args->arg2, (u32)args->arg3, (u16)args->arg4);
}

static struct hook_record hooks[] = {
    { 0, 0, after_security_setprocattr, 4, false, "security_setprocattr" },
    { 0, 0, 0, 0, false, "security_context_to_sid" },
    { 0, 0, 0, 0, false, "security_context_str_to_sid" },
    { 0, 0, 0, 0, false, "security_context_to_sid_force" },
    { 0, before_security_secctx_to_secid, after_security_secctx_to_secid, 3, false, "security_secctx_to_secid" },
    { 0, 0, after_security_secid_to_secctx, 3, false, "security_secid_to_secctx" },
    { 0, 0, 0, 0, false, "security_compute_av_user" },
    { 0, 0, 0, 0, false, "security_compute_av" },
    { 0, before_selinux_setprocattr, after_selinux_setprocattr, 3, false, "selinux_setprocattr" },
    { 0, 0, 0, 0, false, "security_bounded_transition" },
    { 0, 0, 0, 0, false, "security_validate_transition" },
    { 0, 0, 0, 0, false, "security_validate_transition_user" },
};

static void resolve_symbols(void)
{
    sym_security_setprocattr =
        (security_setprocattr_t)kallsyms_lookup_name("security_setprocattr");
    sym_security_context_to_sid =
        (security_context_to_sid_t)kallsyms_lookup_name("security_context_to_sid");
    sym_security_context_str_to_sid =
        (security_context_str_to_sid_t)kallsyms_lookup_name("security_context_str_to_sid");
    sym_security_context_to_sid_force =
        (security_context_to_sid_force_t)kallsyms_lookup_name("security_context_to_sid_force");
    sym_security_secctx_to_secid =
        (security_secctx_to_secid_t)kallsyms_lookup_name("security_secctx_to_secid");
    sym_security_secid_to_secctx =
        (security_secid_to_secctx_t)kallsyms_lookup_name("security_secid_to_secctx");
    sym_security_compute_av_user =
        (security_compute_av_user_t)kallsyms_lookup_name("security_compute_av_user");
    sym_security_compute_av =
        (security_compute_av_t)kallsyms_lookup_name("security_compute_av");
    sym_task_pid_nr_ns =
        (typeof(sym_task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    sym_selinux_setprocattr = (void *)kallsyms_lookup_name("selinux_setprocattr");
    sym_security_bounded_transition = (void *)kallsyms_lookup_name("security_bounded_transition");
    sym_security_validate_transition = (void *)kallsyms_lookup_name("security_validate_transition");
    sym_security_validate_transition_user = (void *)kallsyms_lookup_name("security_validate_transition_user");

    selinux_compat = need_selinux_compat_signature();

    hooks[0].addr = sym_security_setprocattr;
    hooks[1].addr = sym_security_context_to_sid;
    hooks[2].addr = sym_security_context_str_to_sid;
    hooks[3].addr = sym_security_context_to_sid_force;
    hooks[4].addr = sym_security_secctx_to_secid;
    hooks[5].addr = sym_security_secid_to_secctx;
    hooks[6].addr = sym_security_compute_av_user;
    hooks[7].addr = sym_security_compute_av;
    hooks[8].addr = sym_selinux_setprocattr;
    hooks[9].addr = sym_security_bounded_transition;
    hooks[10].addr = sym_security_validate_transition;
    hooks[11].addr = sym_security_validate_transition_user;

    if (selinux_compat) {
        hooks[1].before = before_context_to_sid_compat;
        hooks[1].after = after_context_to_sid_compat;
        hooks[1].argno = 5;
        hooks[2].before = before_context_str_to_sid_compat;
        hooks[2].after = after_context_str_to_sid_compat;
        hooks[2].argno = 4;
        hooks[3].before = before_context_to_sid_force_compat;
        hooks[3].after = after_context_to_sid_force_compat;
        hooks[3].argno = 4;
        hooks[6].after = after_security_compute_av_user_compat;
        hooks[6].argno = 5;
        hooks[7].after = after_security_compute_av_compat;
        hooks[7].argno = 6;
        hooks[9].after = after_security_bounded_transition_compat;
        hooks[9].argno = 3;
        hooks[10].after = after_security_validate_transition_compat;
        hooks[10].argno = 5;
        hooks[11].after = after_security_validate_transition_compat;
        hooks[11].argno = 5;
    } else {
        hooks[1].before = before_context_to_sid;
        hooks[1].after = after_context_to_sid;
        hooks[1].argno = 4;
        hooks[2].before = before_context_str_to_sid;
        hooks[2].after = after_context_str_to_sid;
        hooks[2].argno = 3;
        hooks[3].before = before_context_to_sid_force;
        hooks[3].after = after_context_to_sid_force;
        hooks[3].argno = 3;
        hooks[6].after = after_security_compute_av_user;
        hooks[6].argno = 4;
        hooks[7].after = after_security_compute_av;
        hooks[7].argno = 5;
        hooks[9].after = after_security_bounded_transition;
        hooks[9].argno = 2;
        hooks[10].after = after_security_validate_transition;
        hooks[10].argno = 4;
        hooks[11].after = after_security_validate_transition;
        hooks[11].argno = 4;
    }
}

static int install_hooks(void)
{
    size_t i;
    int ok = 0;

    if (hooks_installed) return 0;
    resolve_symbols();
    pr_info(LOG_PREFIX "kernel=%x selinux_compat_signature=%d\n", kver, selinux_compat ? 1 : 0);
    for (i = 0; i < ARRAY_SIZE_LOCAL(hooks); i++) {
        hook_err_t err;

        if (!hooks[i].addr) {
            pr_warn(LOG_PREFIX "symbol not found: %s\n", hooks[i].name);
            continue;
        }
        err = hook_wrap(hooks[i].addr, hooks[i].argno, hooks[i].before, hooks[i].after, (void *)hooks[i].name);
        if (err == HOOK_NO_ERR) {
            hooks[i].installed = true;
            ok++;
            pr_info(LOG_PREFIX "hooked %s at %llx\n", hooks[i].name, (unsigned long long)hooks[i].addr);
        } else {
            pr_err(LOG_PREFIX "hook failed: %s err=%d addr=%llx\n", hooks[i].name, err,
                   (unsigned long long)hooks[i].addr);
        }
    }
    hooks_installed = ok > 0;
    return ok ? 0 : -1;
}

static void uninstall_hooks(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE_LOCAL(hooks); i++) {
        if (!hooks[i].installed || !hooks[i].addr) continue;
        hook_unwrap(hooks[i].addr, hooks[i].before, hooks[i].after);
        hooks[i].installed = false;
        pr_info(LOG_PREFIX "unhooked %s\n", hooks[i].name);
    }
    hooks_installed = false;
}

static long selinux_query_guard_init(const char *args, const char *event, void *__user reserved)
{
    pr_info(LOG_PREFIX "init event=%s args=%s\n", event ? event : "(null)", args ? args : "(null)");
    return install_hooks();
}

static long selinux_query_guard_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *msg;
    int i;
    int installed = 0;

    if (args && !strcmp(args, "reinstall")) {
        uninstall_hooks();
        install_hooks();
    }

    for (i = 0; i < (int)ARRAY_SIZE_LOCAL(hooks); i++) {
        if (hooks[i].installed) installed++;
    }

    if (installed <= 0)
        msg = "selinux-query-guard hooks=none";
    else if (selinux_compat)
        msg = "selinux-query-guard hooks=installed modify=1 compat=1";
    else
        msg = "selinux-query-guard hooks=installed modify=1 compat=0";

    compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    pr_info(LOG_PREFIX "ctl0 args=%s installed=%d modify=1 compat=%d av_logs=%lu learned_uid=%u learned_iso_uid=%u learned_tgid=%d\n",
            args ? args : "(null)", installed, selinux_compat ? 1 : 0, av_log_count,
            (unsigned int)learned_probe_uid, (unsigned int)learned_probe_isolated_uid, learned_probe_tgid);
    return 0;
}

static long selinux_query_guard_exit(void *__user reserved)
{
    pr_info(LOG_PREFIX "exit\n");
    uninstall_hooks();
    return 0;
}

KPM_INIT(selinux_query_guard_init);
KPM_CTL0(selinux_query_guard_control0);
KPM_EXIT(selinux_query_guard_exit);
