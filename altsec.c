/*
 * Copyright (c) 2021 Wladmis <dev@wladmis.org>
 * Copyright (c) 2023-2025 Wladmis <dev@wladmis.org>
 *
 * SPDX-License-Identifier: MIT OR X11
 */

#include "version.h"

#define _free(x) if (x) { free(x); x = NULL; }
#define unlikely(x) __builtin_expect(!!(x), 0)
#define X_REGISTRY_REQUEST
#define _DEFAULT_SOURCE

#include <xorg-server.h>
#include <xf86.h>
#include <xf86Module.h>
#include <extension.h>
#include <xacestr.h>
#include <os.h>
#include <dix.h>
#include <inputstr.h>
#include <privates.h>
#include <registry.h>
#include <windowstr.h>
#include <window.h>

#include <X11/Xatom.h>

#include <sys/types.h>
#include <sys/stat.h>
#if __linux__
#include <sys/sysmacros.h>
#endif
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    LL_DEFAULT,
    LL_INFO,
    LL_DEBUG,
    LL_TRACE
};

#define ALTSEC "ALTSecurity"
#define DEBUG(...) if (loglevel >= LL_DEBUG) LogMessage(X_INFO, ALTSEC " (debug): " __VA_ARGS__)
#define INFO(...) if (loglevel >= LL_INFO) LogMessage(X_INFO, ALTSEC " (info): " __VA_ARGS__)
#define LOG(...) LogMessage(X_INFO, ALTSEC ": " __VA_ARGS__)

int loglevel = 0;
int spy_mode = 0;

int trusted_uid = -1;
#if __linux__
ino_t root_userns = 0;
ino_t rootdir = 0;
unsigned int rootdir_major = 0;
unsigned int rootdir_minor = 0;
int suid_is_trusted = 1;
int sgid_is_trusted = 1;
#endif /* __linux__ */

/* A Window Manager is trusted client that by altsec design is allowed
 * almost anything Xorg can provide. Altsec keeps its pid because WM can create
 * different X11 clients, for example in the case of reconfiguration. To ensure
 * there is no a pid collision altsec also keep WM command name and arguments. */
pid_t wmpid = -1; /* contains the Window Manager pid */
int wmcid = -1; /* contains the Window Manager cid */
int wmccnt = 0; /* Number of WM clients */

pid_t selection_owner = -1;

DevPrivateKeyRec asec_client_key_rec;
#define asec_client_key (&asec_client_key_rec)
typedef struct {
    int live;
    int spymode;
    pid_t pid;
    int cid;
    int uid;
    int is_suid;
    int is_sgid;
    char *cmdname; /* just for info, do not rely on it: can be faked */
#if __linux__
    /* the executable stats */
    unsigned int major;
    unsigned int minor;
    ino_t ino;
    /* the (ch)root path stats */
    unsigned int root_major;
    unsigned int root_minor;
    ino_t root_ino;
    /* namespace */
    ino_t userns;
#endif /* __linux__ */
    int wm; /* True if the client is a window manager process */
    int is_trusted;
    TimeStamp ts;
} AClientPrivRec, *AClientPrivPtr;

DevPrivateKeyRec asec_prop_key_rec;
#define asec_prop_key (&asec_prop_key_rec)
DevPrivateKeyRec asec_window_key_rec;
#define asec_window_key (&asec_window_key_rec)
DevPrivateKeyRec asec_sel_key_rec;
#define asec_sel_key (&asec_sel_key_rec)
typedef struct {
    /* Common fields. */
    int uid;
    pid_t pid;
    int cid;
    TimeStamp ts;

    /* Properties-only. */
    /* The value of a global property can be read by any client.
     * All properties in the trusted mode or by Window Manager are global. */
    int wm; /* property is handled by window manager */

    /* Selection-only. */
    int is_faked;
} APrivateRec, *APrivatePtr;

#if __linux__
typedef struct {
    ino_t ino;
    unsigned int major;
    unsigned int minor;
} asec_inode;
#endif /* __linux__ */

/**
 * These lists are considered as hacks and
 * will be removed in the future in favor
 * of more granular local policies.
 */
char **add_ext_list = NULL;
char **shared_props_list = NULL;
#if __linux__
asec_inode **trusted_clients_list = NULL;
#endif /* __linux__ */
int permanent = 1;
int strict = 1;

/* Similar from X11 Security extension */
const Mask ALTSecResourceMask =
DixGetAttrAccess | DixReceiveAccess | DixListPropAccess |
DixGetPropAccess | DixListAccess;

const Mask ALTSecSecurityWindowExtraMask = DixRemoveAccess;
const Mask ALTSecSecurityRootWindowExtraMask =
DixReceiveAccess | DixSendAccess | DixAddAccess | DixRemoveAccess;
const Mask ALTSecClientMask = DixGetAttrAccess;

static void altsecModuleInit(INITARGS);
void altsecExtensionInit(void);

static MODULESETUPPROTO(altsecSetup);

ExtensionModule altsecExt =
{
    altsecModuleInit,
    "ALTSecurity",
    NULL
};

static XF86ModuleVersionInfo altsecVerRec = {
    "altsec",
    "Wladmis",
    MODINFOSTRING1,
    MODINFOSTRING2,
    XORG_VERSION_CURRENT,
    MAJORV, MINORV, PATCHL,
    ABI_CLASS_EXTENSION,
    ABI_EXTENSION_VERSION,
    MOD_CLASS_EXTENSION,
    {0, 0, 0, 0}
};

typedef enum {
    OPTION_ALLOWED_EXTS,
    OPTION_LOGLEVEL,
    OPTION_PERMANENT,
    OPTION_SHARED_PROPS,
    OPTION_STRICT,
    OPTION_TRUSTEDCLIENTS,
    OPTION_TRUSTSGID,
    OPTION_TRUSTSUID,
    OPTION_SPYMODE,
    THE_END_OF_OPTIONS
} ALTSecOpts;

static OptionInfoRec ALTSecOptions[] = {
    {OPTION_ALLOWED_EXTS,	"AllowedExts",		OPTV_STRING,	{0},	FALSE},
    {OPTION_LOGLEVEL,		"LogLevel",		OPTV_INTEGER,	{0},	FALSE},
    {OPTION_PERMANENT,		"Permanent",		OPTV_BOOLEAN,	{0},	FALSE},
    {OPTION_SHARED_PROPS,	"SharedProps",		OPTV_STRING,	{0},	FALSE},
    {OPTION_STRICT,		"Strict",		OPTV_BOOLEAN,	{0},	FALSE},
#if __linux__
    {OPTION_TRUSTEDCLIENTS,	"TrustedClients",	OPTV_STRING,	{0},	FALSE},
    {OPTION_TRUSTSGID,		"TrustSGID",		OPTV_BOOLEAN,	{0},	TRUE},
    {OPTION_TRUSTSUID,		"TrustSUID",		OPTV_BOOLEAN,	{0},	TRUE},
#endif /* __linux__ */
    {OPTION_SPYMODE,		"SpyMode",		OPTV_BOOLEAN,	{0},	FALSE},
    {-1,			NULL,			OPTV_NONE,	{0},	FALSE}
};

_X_EXPORT XF86ModuleData altsecModuleData = { &altsecVerRec, altsecSetup, NULL };

static void
free_str_list(char **lst)
{
    if (lst == NULL)
	return;

    for (char **iter = lst; *iter; iter++)
	free(*iter);

    free(lst);
}

/* Make NULL-terminated list of stings */
static char **
make_str_list(const char *str)
{
    char *dstr;
    char *elem, *saveptr, **lst, **tmp;
    size_t num, size;

    if (!str)
	return NULL;

    dstr = strdup(str);

    if (dstr == NULL)
	FatalError(ALTSEC " make_str_list: could not allocate memory for dstr: %s",
		   strerror(errno));

    elem = strtok_r(dstr, ":", &saveptr);

    if (!elem) {
	free(dstr);
	return NULL;
    }

    num = 0;
    size = 4;
    lst = calloc(size, sizeof(*lst));

    do {
	lst[num] = strdup(elem);
	if (lst[num] == NULL)
	    FatalError("make_str_list: could not allocate memory for lst[%lu]: %s",
		       num, strerror(errno));
	num++;

	if (num == size) {
	    size *= 2;
	    tmp = reallocarray(lst, size, sizeof(*lst));

	    if (!tmp) {
		free_str_list(lst);
		lst = NULL;
		goto err;
	    }

	    lst = tmp;
	}
    } while ((elem = strtok_r(NULL, ":", &saveptr)) != NULL);

    lst[num] = NULL;

    tmp = reallocarray(lst, (num + 1), sizeof(*lst));

    if (!tmp) {
	free_str_list(lst);
	lst = NULL;
	goto err;
    }

    lst = tmp;

err:
    free(dstr);
    return lst;
}

static int
is_matched(const char *str, const char **list)
{
    if (!list)
	return 0;

    for (const char **iter = list; *iter; iter++)
	if (strcmp(*iter, str) == 0)
	    return 1;

    return 0;
}

struct {
    int on;
    int cid;
#if __linux__
    ino_t ino, root_ino, userns;
    int uid;
    int major, minor;
#endif /* __linux__ */
} SpyClient;

static int
is_spyclient(AClientPrivPtr client_priv)
{
    if (client_priv->spymode)
	return 1;

#if __linux__
    if (!SpyClient.on)
	return 0;

    if (client_priv->ino != SpyClient.ino
     || client_priv->userns != SpyClient.userns
     || client_priv->root_ino != SpyClient.root_ino
     || client_priv->major != SpyClient.major
     || client_priv->minor != SpyClient.minor
     || client_priv->uid != SpyClient.uid)
	return 0;

    return 1;
#else /* ! __linux__ */
    return 0;
#endif /* __linux__ */

}

static int
is_trusted_uid(int uid)
{
    if (trusted_uid == -1)
	return 1;

    if (uid == trusted_uid || uid == 0)
	return 1;

    return 0;
}

static int
is_trusted_client(ClientPtr client)
{
    AClientPrivPtr subj;

    subj = dixLookupPrivate(&client->devPrivates, asec_client_key);

    return subj->is_trusted;
}

static int
is_proc_client_trusted(AClientPrivPtr client)
{
    if (!is_trusted_uid(client->uid))
	return 0;

    /* TODO: add proper support for non-Linux systems. */
#if __linux__
    /* If we do not know information about real /,
     * we cannot make decision about trusting
     * clients. */
    if (rootdir == 0 || root_userns == 0)
	return 0;

    /* Chrooted clients are not trusted. */
    if (rootdir != client->root_ino
     || rootdir_major != client->root_major
     || rootdir_minor != client->root_minor) {
	DEBUG("is_proc_client_trusted: client #%d (%s) is chrooted\n",
		client->cid, client->cmdname);
	return 0;
    }

    /* Sandboxed clients are not trusted. */
    if (root_userns != client->userns) {
	DEBUG("is_proc_client_trusted: client #%d (%s) is sandboxed\n",
		client->cid, client->cmdname);
	return 0;
    }
#endif /* __linux__ */

    if (!strict && is_trusted_uid(client->uid))
	return 1;

#if __linux__
    if (suid_is_trusted && client->is_suid)
	return 1;

    if (sgid_is_trusted && client->is_sgid)
	return 1;

    /* Check against trusted clients list. */
    for (asec_inode **tc = trusted_clients_list; *tc; tc++) {
	DEBUG("is_proc_client_trusted: compare client #%d (%s) inodes (%lu vs %lu) and devices ((%u,%u) vs (%u,%u)\n",
		client->cid, client->cmdname,
		client->ino, (*tc)->ino,
		client->major, client->minor,
		(*tc)->major, (*tc)->minor);
	if (client->ino == (*tc)->ino
	 && client->minor == (*tc)->minor
	 && client->major == (*tc)->major)
	    return 1;
    }
#endif /* __linux__ */

    return 0;
}

#if __linux__
void
fill_client_stats(AClientPrivPtr client, pid_t pid)
{
    char path[32]; /* 32 bytes should be enough for sizeof("/proc/%d/(exe|root|ns/user)") */
    struct stat sb;
    int len;

    DEBUG("enter fill_client_stats\n");

    if (unlikely((len = snprintf(path, sizeof(path), "/proc/%d/exe", pid)) >= sizeof(path)))
	LOG("fill_client_stats: path \"%s...\" is longer (%d) than expected, please report bug\n", path, len);

    if (stat(path, &sb) != -1) {
	client->major = major(sb.st_dev);
	client->minor = minor(sb.st_dev);
	client->ino = sb.st_ino;
	DEBUG("fill_client_stats: major == %u, minor == %u, ino == %lu\n",
		client->major, client->minor, client->ino);
    } else {
	LOG("fill_client_stats: could not derefer /proc/%d/exe: %s\n", pid, strerror(errno));
	client->major = 0;
	client->minor = 0;
	client->ino = 0;
    }

    if (unlikely((len = snprintf(path, sizeof(path), "/proc/%d/root", pid)) >= sizeof(path)))
	LOG("fill_client_stats: path \"%s...\" is longer (%d) than expected, please report bug\n", path, len);

    if (stat(path, &sb) != -1) {
	client->root_major = major(sb.st_dev);
	client->root_minor = minor(sb.st_dev);
	client->root_ino = sb.st_ino;
	DEBUG("fill_client_stats: root_major == %u, root_minor == %u, root_ino == %lu\n",
		client->root_major, client->root_minor, client->root_ino);
    } else {
	LOG("fill_client_stats: could not derefer /proc/%d/root: %s\n", pid, strerror(errno));
	client->root_major = 0;
	client->root_minor = 0;
	client->root_ino = 0;
    }

    if (unlikely((len = snprintf(path, sizeof(path), "/proc/%d/ns/user", pid)) >= sizeof(path)))
	LOG("fill_client_stats: path \"%s...\" is longer (%d) than expected, please report bug\n", path, len);

    if (stat(path, &sb) != -1) {
	client->userns = sb.st_ino;
	DEBUG("fill_client_stats: userns == %lu\n", client->userns);
    } else {
	LOG("fill_client_stats: could not derefer /proc/%d/ns/user: %s\n", pid, strerror(errno));
	client->userns = 0;
    }

    if (unlikely((len = snprintf(path, sizeof(path), "/proc/%d/status", pid)) >= sizeof(path)))
	LOG("fill_client_stats: path \"%s...\" is longer (%d) than expected, please report bug\n", path, len);

    static const char uid_str[] = "Uid:";
    static const char gid_str[] = "Gid:";
    char *id_str;
    uid_t id, eid, savedid, fsid;
    FILE *status;
    char *line = NULL;
    size_t size;
    int parsed = 0;
    if ((status = fopen(path, "r")) != NULL) {
	while (getline(&line, &size, status) != -1
		&& parsed < 2) {
	    if (strncmp(line, uid_str, strlen(uid_str))
	     && strncmp(line, gid_str, strlen(gid_str)))
		continue;

	    if (sscanf(line, "%ms %u %u %u %u",
			&id_str, &id, &eid, &savedid, &fsid) > 0) {
		if (id != eid) {
		    if (strcmp(id_str, uid_str) == 0) {
			client->is_suid = 1;
			INFO("fill_client_stats: client #%d is suid: real uid = %u, setuid = %u",
				client->cid, id, eid);
		    } else {
			client->is_sgid = 1;
			INFO("fill_client_stats: client #%d is sgid: real gid = %u, setgid = %u",
				client->cid, id, eid);
		    }
		}
		_free(id_str);
	    }

	    parsed++;
	}

	_free(line);
    } else {
	LOG("fill_client_stats: could not open %s: %s\n", path, strerror(errno));
    }

    DEBUG("leave fill_client_stats\n");
}
#endif /* __linux__ */

static int
are_equal_clients(AClientPrivPtr c1, AClientPrivPtr c2)
{
    if (c1->cid == c2->cid
     && c1->ts.months == c2->ts.months
     && c1->ts.milliseconds == c2->ts.milliseconds)
	return 1;

    if (c1->pid <= 0
     || c2->pid <= 0)
	return 0;

    if (c1->pid == c2->pid)
	return 1;

#if __linux__
    /* In case we don't have stats */
    if (c1->ino == 0 || c2->ino == 0
     || c1->root_ino == 0 || c2->root_ino == 0
     || c1->userns == 0 || c2->userns == 0)
	return 0;

    if (c1->ino == c2->ino
     && c1->uid == c2->uid
     && c1->root_ino == c2->root_ino
     && c1->userns == c2->userns
     && c1->major == c2->major
     && c1->minor == c2->minor
     && c1->root_major == c2->root_major
     && c1->root_minor == c2->root_minor)
	return 1;
#endif /* __linux__ */

    return 0;
}

static int
check_ownership(AClientPrivPtr client, APrivatePtr selection)
{
    if (client->cid == selection->cid
     && client->ts.milliseconds == selection->ts.milliseconds
     && client->ts.months == selection->ts.months)
	return 1;

    if (clients[selection->cid] == NULL)
	return 0;

    AClientPrivPtr sel_client = dixLookupPrivate(&clients[selection->cid]->devPrivates, asec_client_key);

    int ret = are_equal_clients(client, sel_client);

    return ret;
}

#if __linux__
static void
construct_trusted_clients_list(const char *str)
{
    char *path_env = getenv("PATH");

    if (path_env == NULL)
	return;

    path_env = strdup(path_env);

    if (path_env == NULL)
	FatalError("construct_trusted_clients_list: could not allocate memory for path_env: %s\n",
		strerror(errno));

    char **path_lst = make_str_list(path_env);
    char path[PATH_MAX];

    char **tmp = make_str_list(str);
    asec_inode **tcl_tmp = NULL;

    int size = 0;
    for (char **iter = tmp; *iter; iter++, size++);
    trusted_clients_list = calloc(size + 1, sizeof(*trusted_clients_list));
    if (trusted_clients_list == NULL)
	FatalError("construct_trusted_clients_list: "
		"could not allocate memory for trusted_clients_list, size = %d\n",
		size);

    int i = 0;
    int len;
    struct stat sb;
    for (char **iter = tmp; *iter; iter++) {
	/* Absolute path. */
	if ((*iter)[0] == '/') {
	    if (stat(*iter, &sb) != -1) {
		if ((trusted_clients_list[i] = malloc(sizeof(**trusted_clients_list))) == NULL)
		    FatalError("construct_trusted_clients_list: "
			    "could not allocate memory for trusted_clients_list[%d]\n",
			    i);
		trusted_clients_list[i]->ino = sb.st_ino;
		trusted_clients_list[i]->major = major(sb.st_dev);
		trusted_clients_list[i]->minor = minor(sb.st_dev);
		INFO("construct_trusted_clients_list: add %s trusted_clients_list[%d], ino = %lu, (%u,%u)\n",
			*iter, i, trusted_clients_list[i]->ino,
			trusted_clients_list[i]->major, trusted_clients_list[i]->minor);
		i++;
	    } else {
		LOG("construct_trusted_clients_list: "
		    "could not get stats for %s (%s), skipping\n",
		    *iter, strerror(errno));
	    }
	    continue;
	}

	for (char **path_iter = path_lst; *path_iter; path_iter++) {
	    len = strlen(*path_iter);

	    /* A simple attempt to normalize path.
	     * I do not want to make it more complicated and general for now. */
	    if ((*path_iter)[len - 1] == '/')
		len--;

	    int path_len;
	    if (unlikely((path_len = snprintf(path, sizeof(path), "%.*s/%s", len, *path_iter, *iter) >= sizeof(path)))) {
		LOG("construct_trusted_clients_list: path \"%s...\" is longer (%d) than expected, please report bug\n"
		    "construct_trusted_clients_list: could not add %s to TrustedClients\n",
		    path, path_len, *iter);
		continue;
	    }

	    if (stat(path, &sb) < 0 || !(sb.st_mode & S_IFREG))
		continue;

	    if ((trusted_clients_list[i] = malloc(sizeof(**trusted_clients_list))) == NULL)
		    FatalError("construct_trusted_clients_list: "
			    "could not allocate memory for trusted_clients_list[%d]\n",
			    i);
	    trusted_clients_list[i]->ino = sb.st_ino;
	    trusted_clients_list[i]->major = major(sb.st_dev);
	    trusted_clients_list[i]->minor = minor(sb.st_dev);
	    INFO("construct_trusted_clients_list: add %s to trusted_clients_list[%d], ino = %lu, (%u,%u)\n",
		    path, i, trusted_clients_list[i]->ino,
		    trusted_clients_list[i]->major, trusted_clients_list[i]->minor);
	    i++;
	    break;
	}
    }

    size = i;

    trusted_clients_list[i] = NULL;
    DEBUG("construct_trusted_clients_list: trusted_clients_list[%d] = NULL\n", i);

    tcl_tmp = reallocarray(trusted_clients_list, size + 1, sizeof(*trusted_clients_list));
    if (tcl_tmp == NULL)
	FatalError("construct_trusted_clients_list:"
		"could not realloc memory to trusted_clients_list, size = %d\n",
		size);

    trusted_clients_list = tcl_tmp;
}
#endif /* __linux__ */

static void *
altsecSetup(__attribute__ ((unused)) void *module, void *opts, __attribute__ ((unused)) int *errmaj, int *errmin)
{
    void *ret = (void *) 1;

    /* These extensions are needed for modern clients with modern graphical
     * toolkits to work. It's OK to allow them all, because we allow a full
     * access to them only for trusted clients, and only safe subset of
     * operations (handled by resource access for example) allowed for
     * untrusted clients. */
    const char *allowed_ext = "XC-MISC:"
	"BIG-REQUESTS:"
	"DAMAGE:"
	"DOUBLE-BUFFER:"
	"DRI2:"
	"DRI3:"
	"GLX:"
	"Generic Event Extension:"
	"MIT-SHM:"
	"Present:"
	"RANDR:"
	"RENDER:"
	"SECURITY:"
	"SHAPE:"
	"SYNC:"
	"X-Resource:"
	"XFIXES:"
	"XFree86-VidModeExtension:"
	"XInputExtension:"
	"XKEYBOARD:"
	"XVideo:"
	"";
    char *ext_str = strdup(allowed_ext);

    if (ext_str == NULL)
	FatalError("altsecSetup: could not allocate memory for ext_str: %s",
		   strerror(errno));

    xf86ProcessOptions(-1, opts, ALTSecOptions);

    xf86GetOptValInteger(ALTSecOptions, OPTION_LOGLEVEL, &loglevel);
    xf86GetOptValBool(ALTSecOptions, OPTION_PERMANENT, &permanent);
    xf86GetOptValBool(ALTSecOptions, OPTION_STRICT, &strict);
    xf86GetOptValBool(ALTSecOptions, OPTION_SPYMODE, &spy_mode);
#if __linux__
    xf86GetOptValBool(ALTSecOptions, OPTION_TRUSTSGID, &sgid_is_trusted);
    xf86GetOptValBool(ALTSecOptions, OPTION_TRUSTSUID, &suid_is_trusted);
#endif /* __linux__ */

    const char *opt_exts = xf86GetOptValString(ALTSecOptions, OPTION_ALLOWED_EXTS);

    if (opt_exts != NULL) {
	int ext_str_len = strlen(allowed_ext) + strlen(opt_exts) + 1;
	/* I don't care about saving the pointer here, we will exit in case of fail anyway. */
	if ((ext_str = reallocarray(ext_str, ext_str_len, sizeof(char))) == NULL)
	    FatalError(ALTSEC ": Could not allocate memory for extension list.\n");
	strcat(ext_str, opt_exts);
    }

    add_ext_list = make_str_list(ext_str);
    _free(ext_str);

    if (!add_ext_list) {
	ret = NULL;
	goto exit;
    }

    const char *shared_props = xf86GetOptValString(ALTSecOptions, OPTION_SHARED_PROPS);
    if (shared_props != NULL)
	shared_props_list = make_str_list(shared_props);

#if __linux__
    const char *trusted_clients = xf86GetOptValString(ALTSecOptions, OPTION_TRUSTEDCLIENTS);
    if (trusted_clients != NULL)
	construct_trusted_clients_list(trusted_clients);
#endif /* __linux__ */

#if __linux__
    struct stat st;
    /* Assume that you cannot run Xorg in non-root user namespace. */
    if (stat("/proc/self/ns/user", &st) != -1) {
	root_userns = st.st_ino;
	DEBUG("altsecSetup: root namespace value is %lu\n", root_userns);
    } else {
	LOG("altsecSetup: could not obtain a value of root namespace: %s\n",
		strerror(errno));
    }

    if (stat("/proc/self/root", &st) != -1) {
	rootdir = st.st_ino;
	rootdir_major = major(st.st_dev);
	rootdir_minor = minor(st.st_dev);
	DEBUG("altsecSetup: "
	      "rootdir inode value is %lu (%u,%u)\n",
		rootdir, rootdir_major, rootdir_minor);
    } else {
	LOG("altsecSetup: could not obtain values of rootdir: %s\n",
		strerror(errno));
    }
#endif /* __linux__ */

exit:
    if (!ret) {
	_free(add_ext_list);
	_free(shared_props_list);
    } else {
	LoadExtensionList(&altsecExt, 1 , FALSE);
    }

    return ret;
}

static void
altsecModuleInit(INITARGS)
{
    static char once = 0;

    if (!once) {
	once++;

	if (!dixRegisterPrivateKey(asec_client_key, PRIVATE_CLIENT, sizeof(AClientPrivRec))) {
	    FatalError("ALTSecurity: could not register private key asec_client_key\n");
	}

	if (!dixRegisterPrivateKey(asec_window_key, PRIVATE_WINDOW, sizeof(APrivateRec))) {
	    FatalError("ALTSecurity: could not register private key asec_window_key\n");
	}

	if (!dixRegisterPrivateKey(asec_prop_key, PRIVATE_PROPERTY, sizeof(APrivateRec))) {
	    FatalError("ALTSecurity: could not register private key asec_prop_key\n");
	}

	if (!dixRegisterPrivateKey(asec_sel_key, PRIVATE_SELECTION, sizeof(APrivateRec))) {
	    FatalError("ALTSecurity: could not register private key asec_sel_key\n");
	}

	altsecExtensionInit();
    }
}

/*
 * Looks up a request name
 * From xorg-server Xext/security.c
 */
static const char *
SecurityLookupRequestName(ClientPtr client)
{
    return LookupRequestName(client->majorOp, client->minorOp);
}

/* selection type enumeration */
enum {
    ASEC_ST_PRIMARY,
    ASEC_ST_CLIPBOARD,
    ASEC_ST_PROPREQUEST
};

/*
 * Get a client that at the moment has input focus.
 *
 * Return: focused client or NULL if none.
 */
ClientPtr
get_focused_client(void)
{
    if (inputInfo.keyboard != NULL
     && inputInfo.keyboard->focus != NULL
     && inputInfo.keyboard->focus->win != NullWindow)
	return wClient(inputInfo.keyboard->focus->win);
    else
	return NULL;
}

/*
 * Check whether the client focused.
 *
 * client -- client to check.
 *
 * Return value: 1 is success, 0 is fail.
 */
static int
is_client_focused(ClientPtr client)
{
    AClientPrivPtr pClientPriv;
    ClientPtr fkbd = NULL;
    AClientPrivPtr fc;

    pClientPriv = dixLookupPrivate(&client->devPrivates, asec_client_key);

    if ((fkbd = get_focused_client()) == NULL)
	return 0;

    fkbd = wClient(inputInfo.keyboard->focus->win);
    fc = dixLookupPrivate(&fkbd->devPrivates, asec_client_key);
    /* If focused window does not belong to client requested the selection,
     * deny */
    if (!are_equal_clients(fc, pClientPriv))
	return 0;

    return 1;
}

static void
ALTSecClientState(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    NewClientInfoRec *pci = calldata;
    AClientPrivPtr pClientPriv;
    LocalClientCredRec *creds;

    pClientPriv = dixLookupPrivate(&pci->client->devPrivates, asec_client_key);

    switch (pci->client->clientState) {
	case ClientStateInitial:
	    pClientPriv->live = 1;
	    pClientPriv->wm = 0;
	    pClientPriv->pid = (pid_t) 0;
	    pClientPriv->cid = pci->client->index;
	    pClientPriv->uid = -1;
	    pClientPriv->cmdname = NULL;

	    UpdateCurrentTimeIf();

	    pClientPriv->ts = currentTime;

	    /* All clients started before WM are considered trusted */
	    if (wmpid == -1) {
		pClientPriv->is_trusted = 1;
		INFO("client #%d: "
		     "client is trusted as it was started in the insecure mode\n",
		     pci->client->index);
	    } else {
		pClientPriv->is_trusted = 0;
	    }

	    if (!GetLocalClientCreds(pci->client, &creds) && creds != NULL) {
		const char *client_cmdname = GetClientCmdName(pci->client);
		if (client_cmdname)
		    pClientPriv->cmdname = strndup(client_cmdname, 64);

		if (creds->fieldsSet & LCC_PID_SET) {
		    pClientPriv->pid = creds->pid;
#if __linux__
		fill_client_stats(pClientPriv, pClientPriv->pid);
#endif /* __linux__ */
		}

		if (creds->fieldsSet & LCC_UID_SET)
		    pClientPriv->uid = creds->euid;

		INFO("REGISTER client #%d initialized by %s (pid=%d, uid=%d)\n",
			pClientPriv->cid,
			pClientPriv->cmdname,
			pClientPriv->pid,
			pClientPriv->uid
		   );

		/* If Strict option is enabled, and client is on the list
		 * of trusted client, mark it as trusted. */
		if (strict
		 && trusted_uid > 0
		 && is_proc_client_trusted(pClientPriv)) {
		    pClientPriv->is_trusted = 1;
		    INFO("client #%d (%s): client is trusted\n",
			  pClientPriv->cid, pClientPriv->cmdname);
		}

		/* If client is owned by Window Manager mark it*/
		/* FIXME: We should check somehow that it is still a Window
		 * Manager process. Unfortunately different OSes have
		 * different APIs to deal with processes information */
		if (wmpid != -1 && pClientPriv->pid == wmpid) {
		    pClientPriv->wm = 1;
		    pClientPriv->is_trusted = 1;
		    wmccnt++;

		    INFO("Initialized client #%d (%s) by Window Manager\n",
			    pClientPriv->cid, pClientPriv->cmdname);
		}

		FreeLocalClientCreds(creds);
	    }

	    break;

	case ClientStateGone:
	    pClientPriv->live = 0;
	    pClientPriv->spymode = 0;
	    if (pci->client->index == SpyClient.cid) {
		SpyClient.cid = 0;
		SpyClient.on = 0;
	    }

	    INFO("DEREGISTER client #%d (%s)\n", pClientPriv->cid, pClientPriv->cmdname);
	    _free(pClientPriv->cmdname);

	    if (pClientPriv->wm) {
		wmccnt--;

		if (wmccnt == 0) {
		    LOG("!!! Window Manager exited\n");

		    if(!permanent) {
			/* Window Manager exits, stop protecting entities */
			trusted_uid = -1;
			wmpid = -1;
			LOG("!!! Window Manager exited, stop protecting X11 entities\n");
		    }
		}
	    }

	    break;

	default:
	    break;
    }
}

void
ALTSecExtension(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceExtAccessRec *rec = calldata;

    AClientPrivPtr subj;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (is_trusted_client(rec->client))
	return;

    if (is_matched(rec->ext->name, (const char **) add_ext_list))
	return;

    LOG("Extension: Deny client #%d (%s) uid %d access %#x to extension %s\n",
	 rec->client->index, subj->cmdname, subj->uid, rec->access_mode, rec->ext->name);
    rec->status = BadAccess;
}

/*
 * Mostly based on SecurityResource() of Xext/security.c of xorg-server
 */
void
ALTSecResourceAccess(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceResourceAccessRec *rec = calldata;
    AClientPrivPtr subj, obj = NULL;
    XID cid = CLIENT_ID(rec->id);
    /* Allow to set properties and send events so make clipboard work,
     * and let ALTSecProperty handles this */
    Mask allowed = ALTSecResourceMask | DixSetPropAccess;

    if (rec->client == serverClient)
	return;

    if (is_trusted_client(rec->client))
	return;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (is_spyclient(subj) && (rec->access_mode & (DixReadAccess|DixGetAttrAccess)))
	return;

    if (rec->rtype == RT_WINDOW)
	allowed |= ALTSecSecurityWindowExtraMask;

    /* This follows DixWriteAccess for properties,
     * thus allowing clipboard exchange to work. */
    if (rec->rtype == (RC_DRAWABLE|RT_WINDOW))
	allowed |= DixSendAccess;

    if ((rec->rtype == RT_WINDOW) &&
	(rec->access_mode & DixCreateAccess)) {
	WindowPtr pWin = (WindowPtr) rec->res;
	APrivatePtr wobj = dixLookupPrivate(&pWin->devPrivates, asec_window_key);

	wobj->uid = subj->uid;
	wobj->pid = subj->pid;
    }

    /* Similar to Xext/security.c */
    /* special checks for server-owned resources */
    if (cid == 0) {
	if (rec->rtype & RC_DRAWABLE)
	    /* additional operations allowed on root windows */
	    allowed |= ALTSecSecurityRootWindowExtraMask;

	else if (rec->rtype == RT_COLORMAP)
	    /* allow access to default colormaps */
	    allowed = rec->access_mode;

	else
	    /* allow read access to other server-owned resources */
	    allowed |= DixReadAccess;
    }

    if (clients[cid] != NULL) {
	obj = dixLookupPrivate(&clients[cid]->devPrivates, asec_client_key);

	if (are_equal_clients(subj, obj))
	    return;

	if ((!strict && (subj->uid == obj->uid))
	 || ((rec->access_mode | allowed) == allowed))
	    return;
    }

    /* Allow some extensions requests */
    if (cid == 0
     && strcmp(SecurityLookupRequestName(rec->client), "RANDR:SelectInput") == 0)
	return;

    LOG("Resource: Deny client number #%d (cmdname=%s, uid=%d, pid=%d) "
	"access mode 0x%lx to resource 0x%lx "
	"resource type 0x%lx "
	"of client #%d (cmdname=%s, uid=%d, pid=%d), on request %s\n",
	rec->client->index, subj->cmdname, subj->uid, subj->pid,
	(unsigned long)rec->access_mode, (unsigned long)rec->id,
	(unsigned long)rec->rtype,
	cid, obj->cmdname, obj->uid, obj->pid, SecurityLookupRequestName(rec->client));

    rec->status = BadAccess;
}

void
ALTServerAccess(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceServerAccessRec *rec = calldata;
    AClientPrivPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (is_trusted_client(rec->client)
     || (rec->access_mode & (DixGetAttrAccess | DixGrabAccess)))
	return;

    /* extend me */
    LOG("ServerAccess: server management is restricted for client #%d (cmdname=%s, uid=%d, pid=%d)\n",
	rec->client->index, subj->cmdname, subj->uid, subj->pid);
    rec->status = BadAccess;
}

void
ALTSecProperty(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    static const char *AppWinProperties[] = {
	"GDK_VISUALS",
	"WM_CLASS",
	"WM_CLIENT_MACHINE",
	"WM_COMMAND",
	"WM_HINTS",
	"WM_NAME",
	"WM_NORMAL_HINTS",
	"_NET_WM_DESKTOP",
	"_NET_WM_NAME",
	"_NET_WM_STATE",
	"_NET_WM_WINDOW_TYPE",
	"_QT_GET_TIMESTAMP",
	NULL
    };

    static const char *WMProperties[] = {
	"_NET_CLIENT_LIST",
	"_NET_CURRENT_DESKTOP",
	"_NET_DESKTOP_GEOMETRY",
	"_NET_DESKTOP_NAMES",
	"_NET_NUMBER_OF_DESKTOPS",
	"_NET_SUPPORTED",
	"_NET_SUPPORTING_WM_CHECK",
	"_NET_WORKAREA",
	NULL
    };

    static const char *AllowedToReadProps[] = {
	"RESOURCE_MANAGER", /* https://www.x.org/releases/current/doc/man/man3/XResourceManagerString.3.xhtml */
	"SCREEN_RESOURCES",
	"_XSETTINGS_SETTINGS", /* https://specifications.freedesktop.org/xsettings/ */
	NULL
    };

    XacePropertyAccessRec *rec = calldata;

    if (rec->access_mode & DixPostAccess)
	return;

    PropertyPtr pProp = *rec->ppProp;
    ATOM name = (*rec->ppProp)->propertyName;
    const char *propName = NameForAtom(name);

    DEBUG("Property: client #%d access %#x property %s for window, owned by client #%d\n",
	    rec->client->index,
	    rec->access_mode,
	    propName,
	    wClient(rec->pWin)->index);

    if (is_matched(propName, (const char **) shared_props_list))
	return;

    if (is_matched(propName, AllowedToReadProps)
     && (rec->access_mode == DixReadAccess))
	return;

    AClientPrivPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);
    APrivatePtr obj = dixLookupPrivate(&pProp->devPrivates, asec_prop_key);
    AClientPrivPtr wo_priv = dixLookupPrivate(&wClient(rec->pWin)->devPrivates, asec_client_key);

    /* Properties are used for inter-client communications, so let's allow to
     * send (i.e. create and write) for anyone, if they are not described in
     * ICCCM and EWMH specs for special usage, but read and destroy by the
     * property or window owners. */
    if (rec->access_mode & (DixCreateAccess|DixWriteAccess)) {
	/* Handle property creation separately */
	if (rec->access_mode & DixCreateAccess) {
	    /* The target window is the root window (I guess) */
	    if (rec->pWin->parent == NULL) {
		DEBUG("Property: client #%d does create access to root window\n",
			rec->client->index);
		/* First client that set on of this properties on the rootwin is
		 * considered as window manager */
		if (trusted_uid == -1 && is_matched(propName, WMProperties)) {
		    trusted_uid = subj->uid;
		    subj->wm = 1;
		    subj->is_trusted = 1;
		    obj->wm = 1;
		    wmpid = subj->pid;
		    wmcid = rec->client->index;
		    wmccnt++;

		    INFO("Client #%d with pid %d is a window manager\n",
			    rec->client->index, rec->client->clientIds->pid);
		    INFO("Transition to the secure mode\n");
		}

		/* According to Application Window Properties specification:
		 * A Client wishing to change the state of a window MUST send a
		 * _NET_WM_STATE client message to the root window. */
		if (is_matched(propName, AppWinProperties))
		    /* allow */;
		else if (rec->client == serverClient)
		    /* allow */;
		else if (is_trusted_client(rec->client))
		    /* allow */;
		else if (!is_matched(propName, WMProperties) || subj->wm)
		    /* allow  if not reserved for WM */;
		else
		    /* Probably break smth */
		    goto deny;
	    } else { /* If not root window */
		if (are_equal_clients(subj, wo_priv)
		 || rec->client == serverClient
		 || is_trusted_client(rec->client)
		 || (!strict && (subj->uid == wo_priv->uid))
		 || !is_matched(propName, AppWinProperties))
		    /* allow */;
		else
		    goto deny;
	    }

	    /* Label newly created property. */
	    if (subj->wm
	     || rec->client == serverClient)
		obj->wm = 1;

	    obj->pid = subj->pid;
	    obj->uid = subj->uid;
	    obj->cid = subj->cid;
	    obj->ts = obj->ts;
	}

	if (check_ownership(subj, obj)
	 || (!strict && (subj->uid == obj->uid)))
	    return;

	if (is_trusted_client(rec->client))
	    return;

	if (are_equal_clients(subj, wo_priv))
	    return;

	if (rec->client == serverClient)
	    return;

	goto deny;
    } else {
	/* Property set by WM is allowed to read by any client */
	if (rec->access_mode & (DixReadAccess|DixGetAttrAccess)) {
	    if (obj->wm || wo_priv->wm)
		return;
	}

	/* Clients in spy mode allowed to read properties */
	if (is_spyclient(subj) && (rec->access_mode & (DixReadAccess|DixGetAttrAccess)))
	    return;

	if (wClient(rec->pWin)->index == 0
	 && (rec->access_mode & (DixReadAccess|DixGetAttrAccess)))
	    return;

	if (check_ownership(subj, obj)
	 || (!strict && (subj->uid == obj->uid)))
	    return;

	if (is_trusted_client(rec->client))
	    return;

	if (are_equal_clients(subj, wo_priv))
	    return;

	goto deny;
    }

    return;

deny:
    LOG("Property: Deny client #%d (cmdname = %s, pid = %d, uid = %d) access %#x to the property %s "
	    "owned by client #%d (window client uid = %d, "
	    "obj->uid = %d, obj->cid = %d, obj->pid = %d, obj->wm = %d)\n",
	rec->client->index, subj->cmdname, subj->pid, subj->uid, rec->access_mode, propName,
	wClient(rec->pWin)->index, wo_priv->uid,
	obj->uid, obj->cid, obj->pid, obj->wm);

    rec->status = BadAccess;
}

/* based on xorg-server Xext/security.c */
void
ALTSecSend(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceSendAccessRec *rec = calldata;
    AClientPrivPtr subj;
    AClientPrivPtr obj;

    if (loglevel >= LL_TRACE)
	for (int i = 0; i < rec->count; i++)
	    if ((rec->dev == inputInfo.keyboard && rec->events[i].u.u.type != KeyPress
						&& rec->events[i].u.u.type != KeyRelease)
	     || (rec->dev == inputInfo.pointer && rec->events[i].u.u.type != ButtonPress
					       && rec->events[i].u.u.type != ButtonRelease))
		LOG("Send (trace): (client #%d or device '%s') is sending event %s to window, owned by client #%d\n",
			rec->client ? rec->client->index : -1,
			rec->dev ? rec->dev->name : "(none)",
			LookupEventName(rec->events[i].u.u.type),
			rec->pWin ? wClient(rec->pWin)->index : -1);

    if (rec->client) {
	subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

	if (is_trusted_client(rec->client))
	    return;

	obj = dixLookupPrivate(&wClient(rec->pWin)->devPrivates, asec_client_key);

	if (!strict && (subj->uid == obj->uid))
	    return;

	if (are_equal_clients(subj, obj))
	    return;

	for (int i = 0; i < rec->count; i++) {
	    int evtype = rec->events[i].u.u.type & 127;
	    if (evtype == UnmapNotify
	     || evtype == ConfigureRequest
	     || evtype == ClientMessage
	     || evtype == SelectionNotify
	     || evtype == PropertyNotify
	     || evtype == DestroyNotify) {
		continue;
	    } else {
		LOG("Send: Deny client #%d (cmdname = %s, uid=%d, pid=%d) "
		    "from sending event of type %s to window 0x%lx of "
		    "client #%d (uid=%d, pid=%d)\n",
			rec->client->index, subj->cmdname, subj->uid, subj->pid,
			LookupEventName(evtype),
			(unsigned long)rec->pWin->drawable.id,
			wClient(rec->pWin)->index, obj->uid, obj->pid);
		rec->status = BadAccess;
		return;
	    }
	}
    }
}

/* based on xorg-server Xext/security.c */
void
ALTSecReceive(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceReceiveAccessRec *rec = calldata;

    AClientPrivPtr subj, obj;
    Atom event;

    if (loglevel >= LL_TRACE)
	for (int i = 0; i < rec->count; i++)
	    if (rec->events[i].u.u.type != KeyPress
	     && rec->events[i].u.u.type != KeyRelease
	     && rec->events[i].u.u.type != ButtonPress
	     && rec->events[i].u.u.type != ButtonRelease)
		LOG("Receive (trace): client #%d is going to receive event %s\n",
			rec->client->index,
			LookupEventName(rec->events[i].u.u.type));

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);
    obj = dixLookupPrivate(&(wClient(rec->pWin))->devPrivates, asec_client_key);

    for (int i = 0; i < rec->count; i++) {
	if (are_equal_clients(subj, obj))
	    continue;

	if (is_trusted_client(rec->client))
	    continue;

	if (rec->client->index == wClient(rec->pWin)->index)
	    continue;

	if (wClient(rec->pWin) == serverClient)
	    continue;

	if ((!strict && (subj->uid == obj->uid)))
	    continue;

	if (rec->events[i].u.u.type == PropertyNotify
	 || rec->events[i].u.u.type == DestroyNotify) {
	    continue;
	}

	event = rec->events[i].u.u.type;

	goto deny;
    }

    return;

deny:
    LOG("Receive: Deny client #%d (%s) to receive message %s (%d) sent to window belonged to client #%d\n",
	    rec->client->index,
	    subj->cmdname,
	    LookupEventName(event),
	    event,
	    wClient(rec->pWin)->index);
    rec->status = BadAccess;
}

void
ALTSecSelection(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceSelectionAccessRec *rec = calldata;

    if (!rec)
	return;

    if (!rec->client)
	return;

    AClientPrivPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    Selection *pSel = *rec->ppSel;

    if (!pSel || !pSel->selection)
	return;

    APrivatePtr obj = dixLookupPrivate(&pSel->devPrivates, asec_sel_key);

    Atom name = pSel->selection;
    const char *atom_name = NameForAtom(name);

    if (!atom_name)
	return;

    if (strcmp(atom_name, "PRIMARY") != 0 &&
	strcmp(atom_name, "CLIPBOARD") != 0)
	goto passthru;

    /* Don't care about the new content check */
    if (rec->access_mode & DixPostAccess)
        return;

    DEBUG("Selection: clipboard selection %s requested by client #%d, access_mode is %#x\n",
	    atom_name,
	    rec->client->index,
	    rec->access_mode);

    if (rec->access_mode & DixCreateAccess) {
	obj->pid = subj->pid;
	obj->cid = subj->cid;
	obj->ts = subj->ts;

	/* Only focused with recent input or trusted clients can own the real
	 * selection, but let others own the faked one to not make them upset. */
	if (is_client_focused(rec->client)
	 || is_trusted_client(rec->client)
	 || rec->client == serverClient) {
	    DEBUG("Selection: Set selection_owner to %d\n", selection_owner);
	    selection_owner = subj->pid;
	    obj->is_faked = 0;
	} else {
	    DEBUG("Selection: faked selection %d\n", subj->pid);
	    obj->is_faked = 1;
	}
    } else {
	int is_permitted;

	if (is_trusted_client(rec->client))
	    is_permitted = 1;
	else
	    is_permitted = is_client_focused(rec->client);

	while (pSel->selection != name
	   || (obj->is_faked && is_permitted)
	   || (!is_permitted && !check_ownership(subj, obj))) {
	    if ((pSel = pSel->next) == NULL)
		break;
	    obj = dixLookupPrivate(&pSel->devPrivates, asec_sel_key);
	}
    }

    if (pSel) {
	*rec->ppSel = pSel;
    } else {
	rec->status = BadMatch;
	LOG("Selection: Deny clipboard selection %s access %#x requested by client #%d (%s): "
	    "not in focus.\n",
	    atom_name, rec->access_mode, rec->client->index, subj->cmdname);
    }

    /* Exit clipboard selection handling. */
    return;

passthru:
    /* Only onwer or trusted client can destroy the selection. */
    if (rec->access_mode & DixDestroyAccess) {
	if (!is_trusted_client(rec->client)
	 || check_ownership(subj, obj))
	    goto deny;
    }

    /* Mark newly created selection. */
    if (rec->access_mode & DixCreateAccess) {
	obj->pid = subj->pid;
	obj->cid = subj->cid;
	obj->ts = subj->ts;
	return;
    }

    /* Allow read access to any client. */
    if ((rec->access_mode & ~(DixReadAccess|DixGetAttrAccess)) == 0)
	return;

    if (is_trusted_client(rec->client))
	return;

    if (check_ownership(subj, obj))
	return;

deny:
    rec->status = BadAccess;
    LOG("Selection: Deny selection %s owned by client #%d access %#x requested by client #%d (%s)\n",
	atom_name, obj->cid, rec->access_mode, rec->client->index, subj->cmdname);
}

void
ALTSecClient(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceClientAccessRec *rec = calldata;
    Mask allowed = ALTSecClientMask;

    if (is_trusted_client(rec->client))
	return;

    AClientPrivPtr subj, obj;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    obj = dixLookupPrivate(&rec->target->devPrivates, asec_client_key);

    if ((!strict && (subj->uid == obj->uid))
     || are_equal_clients(subj, obj)
     || (rec->access_mode | allowed) == allowed)
	return;

    rec->status = BadAccess;
    LOG("Client: Deny client request of uid %d to uid %d\n", subj->uid, obj->uid);
}

void
ALTSecKeyAvailable(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
#define EQUAL_KC 0x0015
    if (!spy_mode)
	return;

    XaceKeyAvailRec *rec = calldata;

    if (rec->event->u.u.type != KeyRelease)
	return;

    if (rec->event->u.u.detail != EQUAL_KC)
	return;

    ClientPtr fkbd;
    if ((fkbd = get_focused_client()) == NULL)
	return;

    AClientPrivPtr client_priv = dixLookupPrivate(&fkbd->devPrivates, asec_client_key);

    if (rec->event->u.keyButtonPointer.state == (ControlMask|Mod1Mask)) {
	client_priv->spymode = 1;
	SpyClient.on = 1;
	SpyClient.cid = fkbd->index;
#if __linux__
	SpyClient.ino = client_priv->ino;
	SpyClient.major = client_priv->major;
	SpyClient.minor = client_priv->minor;
	SpyClient.uid = client_priv->uid;
	SpyClient.userns = client_priv->userns;
	SpyClient.root_ino = client_priv->root_ino;
#endif /* __linux__ */
	INFO("SpyMode: client #%d is in spymode now\n", SpyClient.cid);
    } else if (rec->event->u.keyButtonPointer.state == (ControlMask|Mod1Mask|ShiftMask)
	    && is_spyclient(client_priv)) {
	client_priv->spymode = 0;
	SpyClient.on = 0;
#if __linux__
	if (clients[SpyClient.cid] != NULL) {
	    client_priv = dixLookupPrivate(&clients[SpyClient.cid]->devPrivates, asec_client_key);
	    if (is_spyclient(client_priv)) {
		client_priv->spymode = 0;
	    }
	}
	SpyClient.cid = 0;
#endif /* __linux__ */
	INFO("SpyMode: client #%d is out of spymode now\n", fkbd->index);
    }
}

void
altsecExtensionInit(void)
{
    if (AddCallback(&ClientStateCallback, ALTSecClientState, NULL) != TRUE)
	FatalError("ALTSecurity: could not register client state callback\n");

    if (XaceRegisterCallback(XACE_EXT_DISPATCH, ALTSecExtension, NULL) != TRUE)
	FatalError("ALTSecurity: could not register extension dispatch callback\n");

    if (XaceRegisterCallback(XACE_RESOURCE_ACCESS, ALTSecResourceAccess, NULL) != TRUE)
	FatalError("ALTSecurity: could not register resource access callback\n");

    if (XaceRegisterCallback(XACE_CLIENT_ACCESS, ALTSecClient, NULL) != TRUE) {
	FatalError("ALTSecurity: could not register client callback\n");
    }

    if (XaceRegisterCallback(XACE_PROPERTY_ACCESS, ALTSecProperty, NULL) != TRUE) {
	FatalError("ALTSecurity: could not register property callback\n");
    }

    if (XaceRegisterCallback(XACE_SEND_ACCESS, ALTSecSend, NULL) != TRUE)
	FatalError("ALTSecurity: could not register send callback\n");

    if (XaceRegisterCallback(XACE_RECEIVE_ACCESS, ALTSecReceive, NULL) != TRUE)
	FatalError("ALTSecurity: could not register receive callback\n");

    if (XaceRegisterCallback(XACE_EXT_ACCESS, ALTSecExtension, NULL) != TRUE)
	FatalError("ALTSecurity: could not register extension dispatch callback\n");

    if (XaceRegisterCallback(XACE_SELECTION_ACCESS, ALTSecSelection, NULL) != TRUE) {
	FatalError("ALTSecurity: could not register selection callback\n");
    }

    if (XaceRegisterCallback(XACE_SERVER_ACCESS, ALTServerAccess, NULL) != TRUE) {
	FatalError("ALTSecurity: could not register server access callback\n");
    }

    if (XaceRegisterCallback(XACE_KEY_AVAIL, ALTSecKeyAvailable, NULL) != TRUE) {
	FatalError("ALTSecurity: could not register key available callback\n");
    }
}

/* vim:set shiftwidth=4 noexpandtab: */
