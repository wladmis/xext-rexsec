/*
 * Copyright (c) 2021 Wladmis <dev@wladmis.org>
 * Copyright (c) 2023-2025 Wladmis <dev@wladmis.org>
 *
 * SPDX-License-Identifier: MIT OR X11
 */

#include "version.h"

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
char *root_userns = NULL;
#endif /* __linux__ */

/* A Window Manager is trusted client that by altsec design is allowed
 * almost anything Xorg can provide. Altsec keeps its pid because WM can create
 * different X11 clients, for example in the case of reconfiguration. To ensure
 * there is no a pid collision altsec also keep WM command name and arguments. */
pid_t wmpid = -1; /* contains the Window Manager pid */
int wmcid = -1;
char *wmcmdname = NULL;
char *wmcmdargs = NULL;

pid_t selection_owner = -1;

DevPrivateKeyRec asec_client_key_rec;
#define asec_client_key (&asec_client_key_rec)
typedef struct {
    int live;
    int spymode;
    pid_t pid;
    int uid;
#if __linux__
    /* the executable stats */
    int major;
    int minor;
    ino_t ino;
    /* the (ch)root path stats */
    int root_major;
    int root_minor;
    ino_t root_ino;
    /* namespace */
    ino_t userns;
#endif /* __linux__ */
    int wm; /* True if the client is a window manager process */
    int is_trusted;
    TimeStamp lastInput;
    TimeStamp selReqTS;
    TimeStamp createTime;
    int no_input;
} AClientPrivRec, *AClientPrivPtr;

DevPrivateKeyRec asec_prop_key_rec;
#define asec_prop_key (&asec_prop_key_rec)
typedef struct {
    int uid;
    pid_t pid;
    /* The value of a global property can be read by any client.
     * All properties in the trusted mode or by Window Manager are global. */
    int poly; /* property is polyinstalled */
    int wm; /* property is handled by window manager */
    int is_faked;
} APropPrivRec, *APropPrivPtr;

DevPrivateKeyRec asec_window_key_rec;
#define asec_window_key (&asec_window_key_rec)
typedef struct {
    pid_t pid;
    int uid;
} ASecWinPrivRec, *AWinPrivPtr;

DevPrivateKeyRec asec_sel_key_rec;
#define asec_sel_key (&asec_sel_key_rec)
typedef struct {
    pid_t pid;
    TimeStamp ts;
    int poly;
    int is_faked;
} ASelPrivRec, *ASelPrivPtr;

/**
 * These lists are considered as hacks and
 * will be removed in the future in favor
 * of more granular local policies.
 */
char **add_ext_list = NULL;
char **shared_props_list = NULL;
char **trusted_clients_list = NULL;
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
    OPTION_SPYMODE,
    THE_END_OF_OPTIONS
} ALTSecOpts;

static OptionInfoRec ALTSecOptions[] = {
    {OPTION_ALLOWED_EXTS,	"AllowedExts",		OPTV_STRING,	{0},	FALSE},
    {OPTION_LOGLEVEL,		"LogLevel",		OPTV_INTEGER,	{0},	FALSE},
    {OPTION_PERMANENT,		"Permanent",		OPTV_BOOLEAN,	{0},	FALSE},
    {OPTION_SHARED_PROPS,	"SharedProps",		OPTV_STRING,	{0},	FALSE},
    {OPTION_STRICT,		"Strict",		OPTV_BOOLEAN,	{0},	FALSE},
    {OPTION_TRUSTEDCLIENTS,	"TrustedClients",	OPTV_STRING,	{0},	FALSE},
    {OPTION_SPYMODE,		"SpyMode",		OPTV_BOOLEAN,	{0},	FALSE},
    {-1,			NULL,			OPTV_NONE,	{0},	FALSE}
};

_X_EXPORT XF86ModuleData altsecModuleData = { &altsecVerRec, altsecSetup, NULL };

/* Make NULL-terminated list of stings */
static char **
make_str_list(const char *str)
{
    char *dstr;
    char *elem, **lst, **tmp;
    size_t num, size;

    if (!str)
	return NULL;

    dstr = strdup(str);

    elem = strtok(dstr, ":");

    if (!elem) {
	free(dstr);
	return NULL;
    }

    num = 0;
    size = 4;
    lst = calloc(size, sizeof(*lst));

    do {
	lst[num++] = elem;

	if (num == size) {
	    size *= 2;
	    tmp = realloc(lst, size * sizeof(*lst));

	    if (!tmp) {
		free(lst);
		return NULL;
	    }

	    lst = tmp;
	}
    } while ((elem = strtok(NULL, ":")) != NULL);

    lst[num] = NULL;

    tmp = realloc(lst, (num + 1) * sizeof(*lst));

    if (!tmp) {
	free(lst);
	return NULL;
    }

    lst = tmp;

    return lst;
}

void
free_str_list(char **lst)
{
    if (lst == NULL)
	return;

    for (char **iter = lst; *iter; iter++)
	free(*iter);

    free(lst);
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

    if (!strict && is_trusted_uid(subj->uid))
	return 1;

    return subj->is_trusted;
}

static int
is_proc_client_trusted(const char *cmdname, pid_t pid)
{
    if (is_matched(cmdname, (const char **) trusted_clients_list))
	return 1;

    /* TODO: add proper support for non-Linux systems. */
#if __linux__
#define REALPATH_ERRFMT "is_proc_client_trusted error during resolving %s: %s\n"
#define REALPATH_ERR LOG(REALPATH_ERRFMT, pid_path, strerror(errno));

    char pid_path[64];
    char resolved_path[PATH_MAX];

    snprintf(pid_path, sizeof(pid_path), "/proc/%d/root", pid);
    DEBUG("is_proc_client_trusted: pid_path == %s\n", pid_path);

    if (realpath(pid_path, resolved_path) == NULL) {
	REALPATH_ERR;
	return 0;
    }

    DEBUG("is_proc_client_trusted: %s -> %s\n", pid_path, resolved_path);

    /* Chrooted clients are not trusted. */
    if (strcmp(resolved_path, "/") != 0)
	return 0;

    if (root_userns != NULL) {
	snprintf(pid_path, sizeof(pid_path), "/proc/%d/ns/user", pid);
	DEBUG("is_proc_client_trusted: pid_path == %s\n", pid_path);
	if (realpath(pid_path, resolved_path) == NULL) {
	    REALPATH_ERR;
	    return 0;
	}

	DEBUG("is_proc_client_trusted: %s -> %s\n", pid_path, resolved_path);

	if (strcmp(root_userns, resolved_path) != 0)
	    return 0;
    }

    snprintf(pid_path, sizeof(pid_path), "/proc/%d/exe", pid);
    DEBUG("is_proc_client_trusted: pid_path == %s\n", pid_path);
    if (realpath(pid_path, resolved_path) == NULL) {
	REALPATH_ERR;
	return 0;
    }

    DEBUG("is_proc_client_trusted: %s -> %s\n", pid_path, resolved_path);

    if (is_matched(resolved_path, (const char **) trusted_clients_list))
	return 1;
#endif /* __linux__ */

    return 0;
}

#if __linux__
void
fill_client_stats(AClientPrivPtr client, pid_t pid)
{
    char path[32]; /* 32 bytes should be enough for sizeof("/proc/%d/(exe|root|ns/user)") */
    struct stat sb;

    DEBUG("enter fill_client_stats\n");

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    if (stat(path, &sb) != -1) {
	client->major = major(sb.st_dev);
	client->minor = major(sb.st_dev);
	client->ino = sb.st_ino;
	DEBUG("fill_client_stats: major == %d, minor == %d, ino == %lu\n",
		client->major, client->minor, client->ino);
    }

    snprintf(path, sizeof(path), "/proc/%d/root", pid);
    if (stat(path, &sb) != -1) {
	client->root_major = major(sb.st_dev);
	client->root_minor = major(sb.st_dev);
	client->root_ino = sb.st_ino;
	DEBUG("fill_client_stats: root_major == %d, root_minor == %d, root_ino == %lu\n",
		client->root_major, client->root_minor, client->root_ino);
    }

    snprintf(path, sizeof(path), "/proc/%d/ns/user", pid);
    if (stat(path, &sb) != -1) {
	client->userns = sb.st_ino;
	DEBUG("fill_client_stats: userns == %lu\n", client->userns);
    }

    DEBUG("leave fill_client_stats\n");
}
#endif /* __linux__ */

static int
are_equal_clients(AClientPrivPtr c1, AClientPrivPtr c2)
{
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

static void
construct_trusted_clients_list(const char *str)
{
    char *path_env = strdup(getenv("PATH"));
    char **path_lst = make_str_list(path_env);
    char path[PATH_MAX];

    char **tmp = make_str_list(str) , **tcl_tmp = NULL;

    int size = 0;
    for (char **iter = tmp; *iter; iter++, size++);
    trusted_clients_list = calloc(size + 1, sizeof(*trusted_clients_list));
    if (trusted_clients_list == NULL)
	FatalError("construct_trusted_clients_list:"
		"could not allocate memory for trusted_clients_list, size = %d\n",
		size);

    int i = 0;
    int len;
    struct stat sb;
    for (char **iter = tmp; *iter; iter++) {
	/* copy abs path as it is. */
	if ((*iter)[0] == '/') {
	    trusted_clients_list[i++] = strdup(*iter);
	    DEBUG("construct_trusted_clients_list: add %s\n", *iter);
	    continue;
	}

	for (char **path_iter = path_lst; *path_iter; path_iter++) {
	    len = strlen(*path_iter);

	    /* A simple attempt to normalize path.
	     * I do not want to make it more complicated and general for now. */
	    if ((*path_iter)[len - 1] == '/')
		len--;

	    snprintf(path, sizeof(path), "%.*s/%s", len, *path_iter, *iter);

	    if (stat(path, &sb) < 0 || !(sb.st_mode & S_IFREG))
		continue;

	    trusted_clients_list[i++] = strdup(path);
	    DEBUG("construct_trusted_clients_list: add %s\n", path);
	    break;
	}
    }

    size = i;

    trusted_clients_list[i] = NULL;

    tcl_tmp = reallocarray(trusted_clients_list, size, sizeof(*trusted_clients_list));
    if (tcl_tmp == NULL)
	FatalError("construct_trusted_clients_list:"
		"could not realloc memory fo trusted_clients_list, size = %d\n",
		size);

    trusted_clients_list = tcl_tmp;
}

static void *
altsecSetup(__attribute__ ((unused)) void *module, void *opts, __attribute__ ((unused)) int *errmaj, int *errmin)
{
    void *ret = (void *) 1;

    /* These extenstions are needed for modern clients with modern graphical
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

    xf86ProcessOptions(-1, opts, ALTSecOptions);

    xf86GetOptValInteger(ALTSecOptions, OPTION_LOGLEVEL, &loglevel);
    xf86GetOptValBool(ALTSecOptions, OPTION_PERMANENT, &permanent);
    xf86GetOptValBool(ALTSecOptions, OPTION_STRICT, &strict);
    xf86GetOptValBool(ALTSecOptions, OPTION_SPYMODE, &spy_mode);

    const char *opt_exts = xf86GetOptValString(ALTSecOptions, OPTION_ALLOWED_EXTS);

    if (opt_exts != NULL) {
	int ext_str_len = strlen(allowed_ext) + strlen(opt_exts) + 1;
	/* I don't care about saving the pointer here, we will exit in case of fail anyway. */
	if ((ext_str = realloc(ext_str, ext_str_len * sizeof(char))) == NULL)
	    FatalError(ALTSEC ": Could not allocate memory for extension list.\n");
	strcat(ext_str, opt_exts);
    }

    add_ext_list = make_str_list(ext_str);
    free(ext_str);

    if (!add_ext_list) {
	ret = NULL;
	goto exit;
    }

    const char *shared_props = xf86GetOptValString(ALTSecOptions, OPTION_SHARED_PROPS);
    if (shared_props != NULL)
	shared_props_list = make_str_list(shared_props);

    const char *trusted_clients = xf86GetOptValString(ALTSecOptions, OPTION_TRUSTEDCLIENTS);
    if (trusted_clients != NULL)
	construct_trusted_clients_list(trusted_clients);

#if __linux__
    /* Assume that you cannot run Xorg in non-root user namespace. */
    if ((root_userns = realpath("/proc/self/ns/user", NULL)) != NULL) {
	DEBUG("altsecSetup: root namespace value is %s\n", root_userns);
    } else {
	DEBUG("altsecSetup: could not obtain a value of root namespace: %s\n",
		strerror(errno));
    }
#endif /* __linux__ */

exit:
    if (!ret) {
	if (add_ext_list)
	    free(add_ext_list);

	if (shared_props_list)
	    free(shared_props_list);
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

	if (!dixRegisterPrivateKey(asec_window_key, PRIVATE_WINDOW, sizeof(AClientPrivRec))) {
	    FatalError("ALTSecurity: could not register private key asec_window_key\n");
	}

	if (!dixRegisterPrivateKey(asec_prop_key, PRIVATE_PROPERTY, sizeof(APropPrivRec))) {
	    FatalError("ALTSecurity: could not register private key asec_prop_key\n");
	}

	if (!dixRegisterPrivateKey(asec_sel_key, PRIVATE_SELECTION, sizeof(ASelPrivRec))) {
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
	    pClientPriv->uid = -1;
	    pClientPriv->lastInput.months = 0;
	    pClientPriv->lastInput.milliseconds = 0;
	    pClientPriv->selReqTS.months = 0;
	    pClientPriv->selReqTS.milliseconds = 0;
	    pClientPriv->no_input = 0;

	    UpdateCurrentTimeIf();

	    pClientPriv->createTime = currentTime;

	    /* All clients started before WM are considered trusted */
	    if (wmpid == -1)
		pClientPriv->is_trusted = 1;
	    else
		pClientPriv->is_trusted = 0;

	    if (!GetLocalClientCreds(pci->client, &creds) && creds != NULL) {
		const char *client_cmdname = GetClientCmdName(pci->client);
		const char *client_cmdargs = GetClientCmdArgs(pci->client);

		if (creds->fieldsSet & LCC_PID_SET)
		    pClientPriv->pid = creds->pid;

#if __linux__
		fill_client_stats(pClientPriv, pClientPriv->pid);
#endif /* __linux__ */

		if (creds->fieldsSet & LCC_UID_SET)
		    pClientPriv->uid = creds->euid;

		if (client_cmdname) {
		    INFO("REGISTER client #%d initialized by %s (pid=%d, uid=%d)\n",
			    pci->client->index,
			    client_cmdname,
			    pClientPriv->pid,
			    pClientPriv->uid
		       );

		    /* If Strict option is enabled, and client is on the list
		     * of trusted client, mark it as trusted. */
		    if (strict
		     && trusted_uid > 0
		     && pClientPriv->uid == trusted_uid
		     && is_proc_client_trusted(client_cmdname, pClientPriv->pid)) {
			pClientPriv->is_trusted = 1;
			INFO("client #%d: client is trusted\n", pci->client->index);
		    }
		}


		/* If client is owned by Window Manager mark it*/
		/* FIXME: We should check somehow that it is still a Window
		 * Manager process. Unfortunatelly different OSes have
		 * different APIs to deal with processes information */
		if (wmpid != -1 && pClientPriv->pid == wmpid) {
		    if (client_cmdname && client_cmdargs
		     && strcmp(client_cmdname, wmcmdname) == 0
		     && strcmp(client_cmdargs, wmcmdargs) == 0) {
			pClientPriv->wm = 1;
			pClientPriv->is_trusted = 1;

			INFO("Initialized client #%d by Window Manager\n",
				pci->client->index);
		    } else {
			INFO("pid %d is no longer owned by"
			    "the Window Manager process\n",
				wmpid);

			wmpid = -1;

			free(wmcmdname);
			free(wmcmdargs);
		    }
		}

		if (!strict && (creds->euid == trusted_uid))
		    pClientPriv->is_trusted = 1;

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

	    if (pClientPriv->wm) {
		LOG("!!! Window Manager exited\n");

		if(!permanent) {
		    /* Window Manager exits, stop protecting entities */
		    trusted_uid = -1;
		    wmpid = -1;
		    free(wmcmdname);
		    free(wmcmdargs);
		    LOG("!!! Window Manager exited, stop protecting X11 entities\n");
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

    LOG("Extension: Deny client #%d uid %d access %#x to extension %s\n",
	    rec->client->index, subj->uid, rec->access_mode, rec->ext->name);
    rec->status = BadAccess;
}

/*
 * Mostly based on SecurityResource() of Xext/security.c of xorg-server
 */
void
ALTSecResourceAccess(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceResourceAccessRec *rec = calldata;
    /* WindowPtr pWin; */
    AClientPrivPtr subj, obj = NULL;
    /* ClientPtr pClient = rec->client; */
    XID cid = CLIENT_ID(rec->id);
    /* Allow to set properties and send events so make clipboard work,
     * and let ALTSecProperty handles this */
    Mask allowed = ALTSecResourceMask | DixSetPropAccess | DixSendAccess; /* Properties have polyinstallation in ALTSec */

    if (rec->client == serverClient)
	return;

    if (is_trusted_client(rec->client))
	return;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (is_spyclient(subj) && (rec->access_mode & (DixReadAccess|DixGetAttrAccess)))
	return;

    if (!strict && is_trusted_uid(subj->uid))
	return;

    if (rec->rtype == RT_WINDOW)
	allowed |= ALTSecSecurityWindowExtraMask;

    if ((rec->rtype == RT_WINDOW) &&
	(rec->access_mode & DixCreateAccess)) {
	WindowPtr pWin = (WindowPtr) rec->res;
	AWinPrivPtr wobj = dixLookupPrivate(&pWin->devPrivates, asec_window_key);

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
	 || (subj->pid == obj->pid)
	 || ((rec->access_mode | allowed) == allowed))
	    return;
    }

    /* Allow some extensions requests */
    if (cid == 0
     && strcmp(SecurityLookupRequestName(rec->client), "RANDR:SelectInput") == 0)
	return;

    LOG("Resource: deny client number #%d (uid=%d, pid=%d) "
	"access mode 0x%lx to resource 0x%lx "
	"resource type 0x%lx "
	"of client #%d (uid=%d, pid=%d), on request %s\n",
	rec->client->index, subj->uid, subj->pid,
	(unsigned long)rec->access_mode, (unsigned long)rec->id,
	(unsigned long)rec->rtype,
	cid, obj->uid, obj->pid, SecurityLookupRequestName(rec->client));

    rec->status = BadAccess;
}

void
ALTServerAccess(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceServerAccessRec *rec = calldata;
    AClientPrivPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (is_trusted_client(rec->client)
     || (!strict && is_trusted_uid(subj->uid))
     || (rec->access_mode & (DixGetAttrAccess | DixGrabAccess)))
	return;

    /* extend me */
    LOG("ServerAccess: server management is restricted for client #%d (uid=%d, pid=%d)\n",
	rec->client->index, subj->uid, subj->pid);
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

    AClientPrivPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);
    APropPrivPtr obj = dixLookupPrivate(&pProp->devPrivates, asec_prop_key);
    AClientPrivPtr wo_priv = dixLookupPrivate(&wClient(rec->pWin)->devPrivates, asec_client_key);

    /* Properties are used for inter-client communications, so let's allow to
     * send (i.e. create and write) for anyone, if they are not described in
     * ICCCM and EWMH specs for special usage, but read and destroy by the
     * property or widnow owners. */
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
		    if (rec->client->clientIds->cmdname)
			wmcmdname = strdup(rec->client->clientIds->cmdname);
		    if (rec->client->clientIds->cmdargs)
			wmcmdname = strdup(rec->client->clientIds->cmdargs);

		    INFO("Client #%d with pid %d is a window manager\n",
			    rec->client->index, rec->client->clientIds->pid);
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
	}

	if (subj->pid == obj->pid
	 || (!strict && (subj->uid == obj->uid)))
	    goto allow_to_write;

	if (is_trusted_client(rec->client))
	    goto allow_to_write;

	if (are_equal_clients(subj, wo_priv))
	    goto allow_to_write;

	if (rec->client == serverClient)
	    goto allow_to_write;

	goto deny;

allow_to_write:
	/* Do not consider a client focused if it set no input hint */
	if (strcmp(propName, "WM_HINTS") == 0
	 && pProp->size >= 5 /* should always be true, but just in case */
	 && (((char *) pProp->data)[0] & (char) 1)) {
	    if (((char *) pProp->data)[4] == 0) {
		DEBUG("WM_HINTS property client #%d will be unfocused\n", wClient(rec->pWin)->index);
		wo_priv->no_input = 1;
	    } else {
		DEBUG("WM_HINTS property client #%d will be focused\n", wClient(rec->pWin)->index);
		wo_priv->no_input = 0;
	    }
	}
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

	if (subj->pid == obj->pid
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
    LOG("Property: Deny client #%d (pid = %d, uid = %d) access %#x to the property %s "
	    "owned by client #%d (window client uid = %d, obj->uid = %d, obj->pid = %d, obj->wm = %d)\n",
	rec->client->index,
	subj->pid,
	subj->uid,
	rec->access_mode,
	propName,
	wClient(rec->pWin)->index,
	wo_priv->uid,
	obj->uid,
	obj->pid,
	obj->wm);

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
		LOG("Send (trace): (client #%d or device '%s') is send ingevent %s to window, owned by client #%d\n",
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

	if (subj->pid == obj->pid)
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
		LOG("Send: deny client #%d (uid=%d, pid=%d) "
		    "from sending event of type %s to window 0x%lx of "
		    "client #%d (uid=%d, pid=%d)\n",
			rec->client->index, subj->uid, subj->pid,
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

	if ((!strict && (subj->uid == obj->uid))
	 || subj->pid == obj->pid)
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
    LOG("Receive: deny client #%d to receive message %s (%d) sent to window belonged to client #%d\n",
	    rec->client->index,
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

    ASelPrivPtr obj = dixLookupPrivate(&pSel->devPrivates, asec_sel_key);

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
	   || (!is_permitted && subj->pid != obj->pid)) {
	    if ((pSel = pSel->next) == NULL)
		break;
	    obj = dixLookupPrivate(&pSel->devPrivates, asec_sel_key);
	}
    }

    if (pSel) {
	*rec->ppSel = pSel;
    } else {
	rec->status = BadMatch;
	LOG("Selection: Deny clipboard selection %s access %#x requested by client #%d: "
	    "not in focus.\n",
	    atom_name, rec->access_mode, rec->client->index);
    }

    /* Exit clipboard selection handling. */
    return;

passthru:
    /* Relax non-clipboard selections for now. */
    INFO("Selection: client #%d access %#x to selection %s\n",
	    rec->client->index, rec->access_mode, atom_name);
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

    if (!strict && is_trusted_uid(subj->uid))
	return;

    obj = dixLookupPrivate(&rec->target->devPrivates, asec_client_key);

    if ((!strict && (subj->uid == obj->uid))
     || are_equal_clients(subj, obj)
     || (rec->access_mode | allowed) == allowed)
	return;

    rec->status = BadAccess;
    LOG("Client: deny client request of uid %d to uid %d\n", subj->uid, obj->uid);
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

/* vim:set shiftwidth=4 softtabstop=4 noexpandtab: */
