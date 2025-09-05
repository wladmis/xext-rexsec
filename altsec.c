/*
 * Copyright (c) 2021 Wladmis <dev@wladmis.org>
 * Copyright (c) 2023-2025 Wladmis <dev@wladmis.org>
 *
 * SPDX-License-Identifier: MIT OR X11
 */

#define X_REGISTRY_REQUEST
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

int trusted_uid = -1;

/* A Window Manager is trusted client that by altsec design is allowed
 * almost anything Xorg can provide. Altsec keeps its pid because WM can create
 * different X11 clients, for example in the case of reconfiguration. To ensure
 * there is no a pid collision altsec also keep WM command name and arguments. */
pid_t wmpid = -1; /* contains the Window Manager pid */
int wmcid = -1;
char *wmcmdname = NULL;
char *wmcmdargs = NULL;

pid_t selection_owner = -1;

struct {
    ClientPtr client;
    int cid;
    int uid;
    pid_t pid;
    TimeStamp ts;
} lastFocused = { NULL, -1, -1, -1, {0, 0}};

DevPrivateKeyRec asec_client_key_rec;
#define asec_client_key (&asec_client_key_rec)
typedef struct {
    pid_t pid;
    int uid;
    int wm; /* True if the client is a window manager process */
    int is_trusted;
    TimeStamp lastInput;
    TimeStamp selReqTS;
    TimeStamp createTime;
    int no_input;
} ALTSecClientRec, *ALTSecClientPtr;

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
} ALTSecPropRec, *ALTSecPropPtr;

DevPrivateKeyRec asec_window_key_rec;
#define asec_window_key (&asec_window_key_rec)
typedef struct {
    pid_t pid;
    int uid;
} ALTSecWinRec, *ALTSecWinPtr;

DevPrivateKeyRec asec_sel_key_rec;
#define asec_sel_key (&asec_sel_key_rec)
typedef struct {
    pid_t pid;
    TimeStamp ts;
    int poly;
    int is_faked;
} ALTSecSelRec, *ALTSecSelPtr;

/**
 * These lists are considered as hacks and
 * will be removed in the future in favor
 * of more granular local policies.
 */
char **ALTSecAllowedExt = NULL;
char **ALTSecSharedProps = NULL;
char **ALTSecSharedSels = NULL;
char **ALTSecTrustedClients = NULL;
int ALTSecPermanent = 1;
int ALTSecStrict = 1;

/* Similar from X11 Security extension */
const Mask ALTSecResourceMask =
DixGetAttrAccess | DixReceiveAccess | DixListPropAccess |
DixGetPropAccess | DixListAccess;

const Mask ALTSecSecurityWindowExtraMask = DixRemoveAccess;
const Mask ALTSecSecurityRootWindowExtraMask =
DixReceiveAccess | DixSendAccess | DixAddAccess | DixRemoveAccess;
const Mask ALTSecClientMask = DixGetAttrAccess;

static void altsecModuleInit(INITARGS);
void altsecExtensionInit();

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
    OPTION_SHARE_SELECTIONS,
    OPTION_STRICT,
    OPTION_TRUSTEDCLIENTS,
    THE_END_OF_OPTIONS
} ALTSecOpts;

static OptionInfoRec ALTSecOptions[] = {
    {OPTION_ALLOWED_EXTS,	"AllowedExts",		OPTV_STRING,	{0},	FALSE},
    {OPTION_LOGLEVEL,		"LogLevel",		OPTV_INTEGER,	{0},	FALSE},
    {OPTION_PERMANENT,		"Permanent",		OPTV_BOOLEAN,	{0},	FALSE},
    {OPTION_SHARED_PROPS,	"SharedProps",		OPTV_STRING,	{0},	FALSE},
    {OPTION_SHARE_SELECTIONS,	"SharedSelections",	OPTV_STRING,	{0},	FALSE},
    {OPTION_STRICT,		"Strict",		OPTV_BOOLEAN,	{0},	FALSE},
    {OPTION_TRUSTEDCLIENTS,	"TrustedClients",	OPTV_STRING,	{0},	FALSE},
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

static int
is_sub_matched(const char *str, const char **list)
{
    if (!list)
	return 0;

    for (const char **iter = list; *iter; iter++)
	if (strncmp(*iter, str, strlen(*iter)) == 0)
	    return 1;

    return 0;
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
    ALTSecClientPtr subj;

    subj = dixLookupPrivate(&client->devPrivates, asec_client_key);

    if (!ALTSecStrict && is_trusted_uid(subj->uid))
	return 1;

    return subj->is_trusted;
}

static int
is_proc_client_trusted(const char *cmdname, pid_t pid)
{
    if (is_matched(cmdname, (const char **) ALTSecTrustedClients))
	return 1;

    /* TODO: add proper support for non-Linux systems. */
#if __linux__
    char exe_path[32]; /* 32 bytes should be enough for sizeof("/proc/%d/exe") */
    char real_path[PATH_MAX];
    char root_path[32]; /* 32 bytes should be enough for sizeof("/proc/%d/root") */
    char real_root_path[PATH_MAX]; /* We do not care about the full path */
    ssize_t len;

    snprintf(root_path, sizeof(root_path), "/proc/%d/root", pid);

    if ((len = readlink(root_path, real_root_path, sizeof(real_root_path))) < 0)
	return 0;

    if (len >= sizeof(real_root_path))
	return 0;

    real_root_path[len] = '\0';

    DEBUG("is_proc_client_trusted: root_path = %s, real_root_path = %s\n",
	    root_path, real_root_path);

    /* Chrooted clients are not trusted. */
    if (strcmp(real_root_path, "/") != 0)
	return 0;

    snprintf(real_path, sizeof(real_path), "/proc/%d/exe", pid);

    do {
	strncpy(exe_path, real_path, sizeof(exe_path));

	if ((len = readlink(exe_path, real_path, sizeof(real_path))) < 0)
	    return 0;

	real_path[len] = '\0';

	DEBUG("is_proc_client_trusted: exe_path = %s, real_path = %s\n",
		exe_path, real_path);

	if (is_matched(real_path, (const char **) ALTSecTrustedClients))
	    return 1;
    } while (strcmp(exe_path, real_path));
#endif /* __linux__ */

    return 0;
}

#if 0
static void
clear_last_focused()
{
    lastFocused.client = NULL;
    lastFocused.cid = -1;
    lastFocused.uid = -1;
    lastFocused.pid = -1;
    lastFocused.ts = (TimeStamp) {0, 0};
}
#endif

static void
construct_trusted_clients_list(const char *str)
{
    char *path_env = strdup(getenv("PATH"));
    char **path_lst = make_str_list(path_env);
    char path[PATH_MAX];

    char **tmp = make_str_list(str) , **tcl_tmp = NULL;

    int size = 0;
    for (char **iter = tmp; *iter; iter++, size++);
    ALTSecTrustedClients = calloc(size + 1, sizeof(*ALTSecTrustedClients));
    if (ALTSecTrustedClients == NULL)
	FatalError("construct_trusted_clients_list:"
		"could not allocate memory for ALTSecTrustedClients, size = %d\n",
		size);

    int i = 0;
    int len;
    struct stat sb;
    for (char **iter = tmp; *iter; iter++) {
	/* copy abs path as it is. */
	if ((*iter)[0] == '/') {
	    ALTSecTrustedClients[i++] = strdup(*iter);
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

	    ALTSecTrustedClients[i++] = strdup(path);
	    DEBUG("construct_trusted_clients_list: add %s\n", path);
	    break;
	}
    }

    size = i;

    ALTSecTrustedClients[i] = NULL;

    tcl_tmp = reallocarray(ALTSecTrustedClients, size, sizeof(*ALTSecTrustedClients));
    if (tcl_tmp == NULL)
	FatalError("construct_trusted_clients_list:"
		"could not realloc memory fo ALTSecTrustedClients, size = %d\n",
		size);

    ALTSecTrustedClients = tcl_tmp;
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
    xf86GetOptValBool(ALTSecOptions, OPTION_PERMANENT, &ALTSecPermanent);
    xf86GetOptValBool(ALTSecOptions, OPTION_STRICT, &ALTSecStrict);

    const char *opt_exts = xf86GetOptValString(ALTSecOptions, OPTION_ALLOWED_EXTS);

    if (opt_exts != NULL) {
	int ext_str_len = strlen(allowed_ext) + strlen(opt_exts) + 1;
	/* I don't care about saving the pointer here, we will exit in case of fail anyway. */
	if ((ext_str = realloc(ext_str, ext_str_len * sizeof(char))) == NULL)
	    FatalError(ALTSEC ": Could not allocate memory for extension list.\n");
	strcat(ext_str, opt_exts);
    }

    ALTSecAllowedExt = make_str_list(ext_str);
    free(ext_str);

    if (!ALTSecAllowedExt) {
	ret = NULL;
	goto exit;
    }

    const char *shared_props = xf86GetOptValString(ALTSecOptions, OPTION_SHARED_PROPS);
    if (shared_props != NULL)
	ALTSecSharedProps = make_str_list(shared_props);

    const char *shared_sels = xf86GetOptValString(ALTSecOptions, OPTION_SHARE_SELECTIONS);
    if (shared_sels != NULL)
	ALTSecSharedSels = make_str_list(shared_sels);

    const char *trusted_clients = xf86GetOptValString(ALTSecOptions, OPTION_TRUSTEDCLIENTS);
    if (trusted_clients != NULL)
	construct_trusted_clients_list(trusted_clients);

exit:
    if (!ret) {
	if (ALTSecAllowedExt)
	    free(ALTSecAllowedExt);

	if (ALTSecSharedProps)
	    free(ALTSecSharedProps);

	if (ALTSecSharedSels)
	    free(ALTSecSharedSels);
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

	if (!dixRegisterPrivateKey(asec_client_key, PRIVATE_CLIENT, sizeof(ALTSecClientRec))) {
	    FatalError("ALTSecurity: could not register private key asec_client_key\n");
	}

	if (!dixRegisterPrivateKey(asec_window_key, PRIVATE_WINDOW, sizeof(ALTSecClientRec))) {
	    FatalError("ALTSecurity: could not register private key asec_window_key\n");
	}

	if (!dixRegisterPrivateKey(asec_prop_key, PRIVATE_PROPERTY, sizeof(ALTSecPropRec))) {
	    FatalError("ALTSecurity: could not register private key asec_prop_key\n");
	}

	if (!dixRegisterPrivateKey(asec_sel_key, PRIVATE_SELECTION, sizeof(ALTSecSelRec))) {
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
 * Check whether allow the client access to clipboard content.
 *
 * client -- client to check.
 * is_selection -- 1 if selection.
 * timegap -- fail if last input interaction was earlier that timegap
 *         milliseconds or 0 to ignore it.
 *
 * Return value: 1 is success, 0 is fail.
 */
static int
checkClipboardAccess(ClientPtr client, int is_selection, unsigned int timegap)
{
    ALTSecClientPtr pClientPriv;
    TimeStamp ClipReq;

    pClientPriv = dixLookupPrivate(&client->devPrivates, asec_client_key);

    /* If focused window does not belong to client requested the selection,
     * deny */
    /* In case of a context menu the focused client can be a server client,
     * it's OK to passthrou it because we are still checking the TSes. */
    if (lastFocused.client == NULL
	|| pClientPriv->pid != lastFocused.pid)
	return 0;

    if (is_selection) {
	ClipReq = pClientPriv->lastInput;
    } else {
	/* Selection property is requested */
	ClipReq = pClientPriv->selReqTS;
    }

   if (timegap == 0)
       return 1;

    UpdateCurrentTimeIf();

    /* Update selReqTS */
    if (is_selection)
	pClientPriv->selReqTS = currentTime;

    /* FIXME: ugly hack */
    if (currentTime.months != ClipReq.months)
	return 0;

    if (currentTime.milliseconds - ClipReq.milliseconds >= timegap)
	return 0;

    return 1;
}

static void
ALTSecClientState(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    NewClientInfoRec *pci = calldata;
    ALTSecClientPtr pClientPriv;
    LocalClientCredRec *creds;

    pClientPriv = dixLookupPrivate(&pci->client->devPrivates, asec_client_key);

    switch (pci->client->clientState) {
	case ClientStateInitial:
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
		    if (ALTSecStrict
			    && trusted_uid > 0
			    && pClientPriv->uid == trusted_uid
			    && is_proc_client_trusted(client_cmdname, pClientPriv->pid)) {
			pClientPriv->is_trusted = 1;
			INFO("client #6: client is trusted\n");
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

		if (!ALTSecStrict && creds->euid == trusted_uid)
		    pClientPriv->is_trusted = 1;

		FreeLocalClientCreds(creds);
	    }

	    break;

	case ClientStateGone:
	    if (pClientPriv->wm) {
		LOG("!!! Window Manager exited\n");

		if(!ALTSecPermanent) {
		    /* Window Manager exits, stop protecting entities */
		    trusted_uid = -1;
		    wmpid = -1;
		    free(wmcmdname);
		    free(wmcmdargs);
		    LOG("!!! Window Manager exited, stop protecting X11 entities\n");
		}
	    }

#if 0
	    if (lastFocused.client == pci->client)
		clear_last_focused();
#endif

	    break;

	default:
	    break;
    }
}

void
ALTSecExtension(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceExtAccessRec *rec = calldata;

    ALTSecClientPtr subj;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (is_trusted_client(rec->client))
	return;

    if (is_matched(rec->ext->name, (const char **) ALTSecAllowedExt))
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
    ALTSecClientPtr subj, obj = NULL;
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

    if (!ALTSecStrict && is_trusted_uid(subj->uid))
	return;

    if (rec->rtype == RT_WINDOW)
	allowed |= ALTSecSecurityWindowExtraMask;

    if ((rec->rtype == RT_WINDOW) &&
	(rec->access_mode & DixCreateAccess)) {
	WindowPtr pWin = (WindowPtr) rec->res;
	ALTSecWinPtr wobj = dixLookupPrivate(&pWin->devPrivates, asec_window_key);

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
	if ((subj->uid == obj->uid) || ((rec->access_mode | allowed) == allowed))
	    return;
    }

    /* Allow some extensions requests */
    if (cid == 0
	    && strcmp(SecurityLookupRequestName(rec->client), "RANDR:SelectInput") == 0)
	return;

    LOG("Resource: deny client number #%d (uid=%d, pid=%d) "
	"access mode %lx to resource 0x%lx "
	"of client id %d (uid=%d, pid=%d), on request %s\n",
	rec->client->index, subj->uid, subj->pid,
	(unsigned long)rec->access_mode, (unsigned long)rec->id,
	cid, obj->uid, obj->pid, SecurityLookupRequestName(rec->client));

    rec->status = BadAccess;
}

void
ALTServerAccess(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceServerAccessRec *rec = calldata;
    ALTSecClientPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (is_trusted_client(rec->client)
	    || (!ALTSecStrict && is_trusted_uid(subj->uid))
	    || (rec->access_mode & (DixGetAttrAccess | DixGrabAccess)))
	return;

    /* extend me */
    LOG("ServerAccess: server management is restricted for client number #%d (uid=%d, pid=%d)\n",
	rec->client->index, subj->uid, subj->pid);
    rec->status = BadAccess;
}

void
ALTSecProperty(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    /* FIXME: handle me in the right way! */
    /* It seems that XACE does not cover SelectionNotify so I cannot obtain
     * information about the right property to handle. */
    /* List of the clipboard properties handled by ALTSec.
     * If HandleClipboard option is enabled, allow to the current focused
     * window to get the clipboard content.
     * The list is probably incomplete */
    static const char *ClipboardProperties[] = {
	"CLIPBOARD",
	"GDK_SELECTION",
	"XCLIP_OUT",
	"_QT_SELECTION",
	"_XT_SELECTION_",
	NULL
    };

    static const char *AppWinProperties[] = {
	"GDK_VISUALS",
	"WM_CLASS",
	"WM_CLIENT_MACHINE",
	"WM_COMMAND",
	"WM_NAME",
	"WM_NORMAL_HINTS",
	"_NET_WM_DESKTOP",
	"_NET_WM_NAME",
	"_NET_WM_STATE",
	"_NET_WM_WINDOW_TYPE",
	"_QT_GET_TIMESTAMP",
	NULL
    };

    XacePropertyAccessRec *rec = calldata;
    int is_selection = 0;

    if (rec->access_mode & DixPostAccess)
	return;

    PropertyPtr pProp = *rec->ppProp;
    ClientPtr client = wClient(rec->pWin);
    ATOM name = (*rec->ppProp)->propertyName;
    const char *propName = NameForAtom(name);
    ALTSecClientPtr subj;
    ALTSecPropPtr obj;
    ALTSecWinPtr wobj;
    Mask allowed = ALTSecResourceMask | DixReadAccess;

    if (loglevel >= LL_TRACE)
	LOG("Property (trace): client #%d access %#x property %s for window, owned by client #%d\n",
		rec->client->index,
		rec->access_mode,
		propName,
		wClient(rec->pWin)->index);

    if (is_matched(propName, (const char **) ALTSecSharedProps))
	return;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);
    obj = dixLookupPrivate(&pProp->devPrivates, asec_prop_key);
    wobj = dixLookupPrivate(&rec->pWin->devPrivates, asec_window_key);

    if (!is_sub_matched(propName, ClipboardProperties))
	goto passthru;

    DEBUG("PropertyAccess: Client #%d uid %d access (access_mode=%#x) clipboard property %s of client #%d\n",
	    client->index, subj->uid, rec->access_mode, propName, rec->client->index);

    if (rec->access_mode & DixCreateAccess) {
	if (checkClipboardAccess(client, 0, 0)
		|| is_trusted_client(client)
		|| subj->pid == obj->pid)
	    obj->is_faked = 0;
	else
	    obj->is_faked = 1;
    } else {
	int is_permitted = checkClipboardAccess(client, 0, 0);
	while (pProp->propertyName != name
		|| (obj->is_faked && is_permitted)
		|| (!is_permitted && subj->pid != obj->pid)) {
	    if ((pProp = pProp->next) == NULL)
		break;
	    obj = dixLookupPrivate(&pProp->devPrivates, asec_prop_key);
	}
    }

    if (pProp) {
	*rec->ppProp = pProp;
    } else {
	rec->status = BadMatch;
	LOG("Property: Deny clipboard property %s access %#x client #%d to client #%d\n",
		propName,
		rec->access_mode,
		rec->client->index,
		client->index);
    }

    return;

    /* Originally, the following code had polyinstallation for properties, but
     * it made it more complex, so I dropped it for now. */
passthru:
    DEBUG("Property: passthru to non clipboard properties.\n");
    /* Hanble non-clipboard properties. */
    if (rec->access_mode & DixCreateAccess) {
	/* Label newly created properties. */
	/* The target window is the root window (I guess) */
	if (rec->pWin->parent == NULL) {
	    DEBUG("Property: client #%d does create access to root window\n",
		    rec->client->index);
	    /* First client that set _NET_SUPPORTED on the rootwin is
	     * considered as window manager */
	    /* TODO: handle other props provided by _NET_SUPPORTED */
	    if (trusted_uid == -1 && strcmp(propName, "_NET_SUPPORTED") == 0) {
		trusted_uid = subj->uid;
		subj->wm = 1;
		obj->wm = 1;
		subj->is_trusted = 1;
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
	    else if (subj->is_trusted)
		/* allow */;
	    else
		/* Probably break smth */
		goto deny;

	} else {
	    if (subj->is_trusted)
		/* allow */;
	    else if (subj->pid > 0 &&
		    (subj->pid == wobj->pid ||
		     subj->pid == obj->pid))
		/* allow */;
	    else if (!ALTSecStrict && subj->uid == wobj->uid)
		/* allow */;
	    else if (rec->client == serverClient)
		/* allow */;
	    else if (rec->client->index == client->index)
		/* allow */;
	    else
		goto deny;
	}

	/* Label property */
	obj->uid = subj->uid;
	obj->pid = subj->pid;

	/* Properties set by a Window Manager can be read by anyone */
	if (subj->wm || rec->client == serverClient)
	    obj->wm = 1;
    } else if (rec->access_mode & allowed
	    || rec->client->index == client->index
	    || (obj->wm && (rec->access_mode & DixReadAccess))
	    || subj->uid == obj->uid
	    || subj->pid == obj->pid
	    || subj->pid == wobj->pid
	    || subj->is_trusted
	    || rec->client == serverClient) {
	return;
    } else {
	goto deny;
    }

    /* Do not consider a client focused if it set no input hint */
    ALTSecClientPtr wcobj = dixLookupPrivate(&client->devPrivates, asec_client_key);
    if (strcmp(propName, "WM_HINTS") == 0
	    && pProp->size >= 5 /* should always be true, but just in case */
	    && (((char *) pProp->data)[0] & (char) 1)) {
	if (((char *) pProp->data)[4] == 0) {
	    DEBUG("WM_HINTS property client #%d will be unfocused\n", client->index);
	    wcobj->no_input = 1;
	} else {
	    DEBUG("WM_HINTS property client #%d will be focused\n", client->index);
	    wcobj->no_input = 0;
	}
    }

    return;

deny:
    LOG("Property: Deny client #%d (pid=%d, uid=%d) access %#x to the property %s owned by client #%d (wobj uid=%d)\n",
	rec->client->index,
	subj->pid,
	subj->uid,
	rec->access_mode,
	propName,
	client->index,
	wobj->uid);

    DEBUG("Property: is_selection: %d\n", is_selection);
    rec->status = is_selection ? BadMatch : BadAccess;
}

/* based on xorg-server Xext/security.c */
void
ALTSecSend(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceSendAccessRec *rec = calldata;
    ALTSecClientPtr subj;
    ALTSecClientPtr obj;

    if (loglevel >= LL_TRACE)
	for (int i = 0; i < rec->count; i++)
	    if ((rec->dev == inputInfo.keyboard
		    && rec->events[i].u.u.type != KeyPress
		    && rec->events[i].u.u.type != KeyRelease)
		|| (rec->dev == inputInfo.pointer
		    && rec->events[i].u.u.type != ButtonPress
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

	if (!ALTSecStrict && subj->uid == obj->uid)
	    return;

	if (subj->pid == obj->pid)
	    return;

	for (int i = 0; i < rec->count; i++) {
	    if ((rec->events[i].u.u.type & 127) != UnmapNotify
		&& (rec->events[i].u.u.type & 127) != ConfigureRequest
		&& (rec->events[i].u.u.type & 127) != ClientMessage
		&& (rec->events[i].u.u.type & 127) != SelectionNotify
		&& (rec->events[i].u.u.type & 127) != PropertyNotify
		&& (rec->events[i].u.u.type & 127) != DestroyNotify) {
		LOG("Send: deny client #%d (uid=%d, pid=%d) "
		    "from sending event of type %s to window 0x%lx of "
		    "client %d (uid=%d, pid=%d)\n",
			rec->client->index, subj->uid, subj->pid,
			LookupEventName(rec->events[i].u.u.type),
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

    ALTSecClientPtr subj, obj;
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
	if (rec->events[i].u.u.type == FocusIn
		&& subj->no_input == 0
		&& rec->client->index != wmcid
		&& rec->client != serverClient) {

	    UpdateCurrentTimeIf();

	    lastFocused.client = rec->client;
	    lastFocused.cid = rec->client->index;
	    lastFocused.uid = subj->uid;
	    lastFocused.pid = subj->pid;
	    lastFocused.ts = currentTime;

	    DEBUG("Receive: focus change: client #%d, uid=%d, pid=%d\n",
		    lastFocused.cid, lastFocused.uid, lastFocused.pid);
	}

	if (is_trusted_client(rec->client))
	    continue;

	if (rec->client->index == wClient(rec->pWin)->index)
	    continue;

	if (wClient(rec->pWin) == serverClient)
	    continue;

	if ((!ALTSecStrict && subj->uid == obj->uid)
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

    ALTSecClientPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    Selection *pSel = *rec->ppSel;

    if (!pSel || !pSel->selection)
	return;

    ALTSecSelPtr obj = dixLookupPrivate(&pSel->devPrivates, asec_sel_key);

    Atom name = pSel->selection;
    const char *atom_name = NameForAtom(name);

    if (!atom_name)
	return;

    if (is_matched(atom_name, (const char **) ALTSecSharedSels))
	return;

    if (strcmp(atom_name, "PRIMARY") != 0 &&
	strcmp(atom_name, "CLIPBOARD") != 0)
	goto passthru;

    DEBUG("Selection: clipboard selection %s requested by client #%d, focused client is #%d, access_mode is %#x\n",
	    atom_name,
	    rec->client->index,
	    lastFocused.cid,
	    rec->access_mode);

    if (rec->access_mode & (DixCreateAccess|DixSetAttrAccess)) {
	obj->pid = subj->pid;
	/* Only focused with recent input or trusted clients can own the real
	 * selection, but let others own the faked one to not make them upset. */
	if (checkClipboardAccess(rec->client, 1, 0)
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
	int is_permitted = checkClipboardAccess(rec->client, 1, 0);
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
	    "not in focus of more than 500 mls passed\n",
	    atom_name, rec->access_mode, rec->client->index);
    }

    /* Exit clipboard selection handling. */
    return;

passthru:
    DEBUG("Selection: passthrou\n");
    /* Originally, the following code had polyinstallation for selections, but
     * it made it more complex, so I dropped it for now. */
    if (rec->access_mode & (DixGetAttrAccess | DixReadAccess)) {
	LocalClientCredRec *creds;
	if (GetLocalClientCreds(rec->client, &creds) || creds == NULL) {
	    goto deny;
	}

	int recuid = creds->euid;
	FreeLocalClientCreds(creds);

	if (!pSel->client)
	    return;

	if (GetLocalClientCreds(pSel->client, &creds) || creds == NULL) {
	    goto deny;
	}

	int seluid = creds->euid;
	FreeLocalClientCreds(creds);

	if (recuid != seluid) {
	    goto deny;
	}
    }

    return;

deny:
    LOG("Selection: Deny selection %s access %#x request by client #%d\n",
	    atom_name, rec->access_mode, rec->client->index);
    rec->status = BadAccess;
    return;
}

void
ALTSecClient(__attribute__ ((unused)) CallbackListPtr *pcbl, __attribute__ ((unused)) void *userdata, void *calldata)
{
    XaceClientAccessRec *rec = calldata;
    Mask allowed = ALTSecClientMask;

    if (is_trusted_client(rec->client))
	return;

    ALTSecClientPtr subj, obj;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (!ALTSecStrict && is_trusted_uid(subj->uid))
	return;

    obj = dixLookupPrivate(&rec->target->devPrivates, asec_client_key);

    if (subj->uid == obj->uid ||
	    (rec->access_mode | allowed) == allowed)
	return;

    rec->status = BadAccess;
    LOG("Client: deny client request of uid %d to uid %d\n", subj->uid, obj->uid);
}

void
altsecExtensionInit()
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
}

/* vim:set shiftwidth=4 softtabstop=4 noexpandtab: */
