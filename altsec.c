#include <xorg-server.h>
#include <xf86.h>
#include <xf86Module.h>
#include <extension.h>
#include <xacestr.h>
#include <os.h>
#include <dix.h>
#include <privates.h>
#include <windowstr.h>
#include <window.h>

#include <X11/Xatom.h>

#include <sys/types.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "altsec.h"

DevPrivateKeyRec asec_client_key_rec;
DevPrivateKeyRec asec_window_key_rec;
DevPrivateKeyRec asec_prop_key_rec;

uid_t priv_uid = -1;

typedef struct {
    unsigned int client_id;
    uid_t uid;
} ALTSecClientRec, *ALTSecClientPtr;

/**
 * These lists are considered as hacks and
 * will be removed in the future in favor
 * of more granual local policies.
 */
char **ALTSecAllowedEXt;
char **ALTSecSharedProps;
char **ALTSecSharedSels;
uid_t *ALTSecPrivUids;

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
    "ALT Linux Team",
    MODINFOSTRING1,
    MODINFOSTRING2,
    XORG_VERSION_CURRENT,
    0, 0, 0,
    ABI_CLASS_EXTENSION,
    ABI_EXTENSION_VERSION,
    MOD_CLASS_EXTENSION,
    {0, 0, 0, 0}
};

typedef enum {
    OPTION_ALLOWED_EXTS,
    OPTION_SHARED_PROPS,
    OPTION_SHARE_SELECTIONS,
    OPTION_PRIV_UIDS
} ALTSecOpts;

static const OptionInfoRec ALTSecOptions[] = {
    {OPTION_ALLOWED_EXTS,	"AllowedExts",		OPTV_STRING,	{0},	FALSE},
    {OPTION_SHARED_PROPS,	"SharedProps",		OPTV_STRING,	{0},	FALSE},
    {OPTION_SHARE_SELECTIONS,	"SharedSelections",	OPTV_STRING,	{0},	FALSE},
    {OPTION_PRIV_UIDS,		"PrivUids",		OPTV_STRING,	{0},	FALSE},
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

static void *
altsecSetup(void *module, void *opts, int *errmaj, int *errmin)
{
    void *ret = (void *) 1;

    /* Similar to X11 Security extension */
    /* The only extensions that untrusted clients have access to */
    const char *allowed_ext = "XC-MISC:BIG-REQUESTS:";
    char *ext_str;

    for (int i = 0; ALTSecOptions[i].name != NULL; i++) {
	const char *val = xf86FindOptionValue(opts, ALTSecOptions[i].name);

	if (val != NULL) {
	    switch (ALTSecOptions[i].token) {
		case OPTION_ALLOWED_EXTS:
		    LogMessage(X_INFO, "AllowedExts: %s\n", val);
		    ext_str = calloc(strlen(allowed_ext) + strlen(val) + 1, sizeof(char));
		    strcat(ext_str, allowed_ext);
		    strcat(ext_str, val);
		    ALTSecAllowedEXt = make_str_list(ext_str);

		    if (!ALTSecAllowedEXt) {
			ret = NULL;
			goto exit;
		    }

		    break;

		case OPTION_SHARED_PROPS:
		    LogMessage(X_INFO, "SharedProps: %s\n", val);
		    ALTSecSharedProps = make_str_list(val);

		    if (!ALTSecSharedProps) {
			ret = NULL;
			goto exit;
		    }

		    break;

		case OPTION_SHARE_SELECTIONS:
		    LogMessage(X_INFO, "SharedSelections: %s\n", val);
		    ALTSecSharedSels = make_str_list(val);

		    if (!ALTSecSharedSels) {
			ret = NULL;
			goto exit;
		    }

		    break;

		case OPTION_PRIV_UIDS:
		    /* make_uid_list(&ALTSecPrivUids, val); */
		    break;

		default:
		    break;
	    }
	}
    }

exit:
    if (!ret) {
	if (ALTSecAllowedEXt)
	    free(ALTSecAllowedEXt);

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
    }

    if (!dixRegisterPrivateKey(asec_client_key, PRIVATE_CLIENT, sizeof(ALTSecClientRec))) {
	FatalError("ALTSecurity: could not register private key asec_client_key\n");
    }

    if (!dixRegisterPrivateKey(asec_window_key, PRIVATE_WINDOW, 0)) {
	FatalError("ALTSecurity: could not register private key asec_window_key\n");
    }

    if (!dixRegisterPrivateKey(asec_prop_key, PRIVATE_PROPERTY, sizeof(ALTSecClientRec))) {
	FatalError("ALTSecurity: could not register private key asec_client_key\n");
    }

    altsecExtensionInit();
}

static void
ALTSecClientState(CallbackListPtr *pcbl, void *userdata, void *calldata)
{
    NewClientInfoRec *pci = calldata;
    ALTSecClientPtr pClientPriv;
    LocalClientCredRec *creds;

    static unsigned int client_id;

    pClientPriv = dixLookupPrivate(&pci->client->devPrivates, asec_client_key);

    switch (pci->client->clientState) {
	case ClientStateInitial:
	    LogMessage(X_INFO, "ALTSecClientState: new client\n");
	    pClientPriv->client_id = client_id++;
	    if (!GetLocalClientCreds(pci->client, &creds) && creds != NULL) {
		pClientPriv->uid = creds->euid;
		LogMessage(X_INFO, "ALTSecClientState: pid: %d, uid: %d, priv_uid: %d\n", creds->pid, creds->euid, priv_uid);
		if (pci->client == serverClient)
		    LogMessage(X_INFO, "Client is a serverClient");

		/* first non-root registred uid is privilleged */
		if (priv_uid == -1 && creds->euid != 0) {
		    LogMessage(X_INFO, "ALTSecClientState: register privilleged uid\n");
		    priv_uid = (uid_t) creds->euid;
		}

		FreeLocalClientCreds(creds);
	    } else {
		pClientPriv->uid = (uid_t) -1;
	    }
	    break;
	default:
	    break;
    }
}

void
ALTSecExtension(CallbackListPtr *pcbl, void *userdata, void *calldata)
{
    XaceExtAccessRec *rec = calldata;

    ALTSecClientPtr subj;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (subj->uid == priv_uid || subj->uid == 0)
	return;

    for (int i = 0; ALTSecAllowedEXt[i]; i++)
	if (!strcmp(ALTSecAllowedEXt[i], rec->ext->name)) {
	    return;
	}

    LogMessage(X_INFO, "ALTSecurity: denied client %d uid %d access to extension %s\n",
	    rec->client->index, subj->uid, rec->ext->name);
    rec->status = BadAccess;
}

/*
 * Mostly based on SecurityResource() of Xext/security.c of xorg-server
 */
void
ALTSecResourceAccess(CallbackListPtr *pcbl, void *userdata, void *calldata)
{
    XaceResourceAccessRec *rec = calldata;
    WindowPtr pWin;
    ALTSecClientPtr subj, obj = NULL;
    ClientPtr pClient = rec->client;
    XID cid = CLIENT_ID(rec->id);
    Mask allowed = ALTSecResourceMask | DixSetPropAccess | DixSendAccess; /* Properties have polyinstallation in ALTSec */

    if (rec->client == serverClient)
	return;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (subj->uid == priv_uid || subj->uid == 0)
	return;

    if ((rec->access_mode & DixCreateAccess) && (rec->rtype == RT_WINDOW))
	((WindowPtr) rec->res)->forcedBG = TRUE;

    if (rec->rtype == RT_WINDOW)
	allowed |= ALTSecSecurityWindowExtraMask;

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

#if 0
    LogMessage(X_INFO, "ALTSecurity: denied client %d access %lx to resource 0x%lx "
	    "of client %d on request %s\n", rec->client->index,
	    (unsigned long)rec->access_mode, (unsigned long)rec->id, cid,
	    LookupRequestName(rec->client->majorOp, rec->client->minorOp));
#endif

    LogMessage(X_INFO, "ALTSecurity: denied client %d uid %d access mode %o to resource type %o id 0x%lx\n",
	    rec->client->index, subj->uid, rec->access_mode, rec->rtype, rec->id);
    rec->status = BadAccess;
}

void
ALTServerAccess(CallbackListPtr *pcbl, void *userdata, void *calldata)
{
    XaceServerAccessRec *rec = calldata;
    ALTSecClientPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (subj->uid == priv_uid
	    || subj->uid == 0
	    || (rec->access_mode & (DixGetAttrAccess | DixGrabAccess)))
	return;

    LogMessage(X_INFO, "ALTSecurity: Enter server access\n");

    /* extend me */
    LogMessage(X_INFO, "ALTSecurity: server management is restricted\n");
    rec->status = BadAccess;
}

#if 0
void
ALTSecAuth(CallbackListPtr *pcbl, void *userdata, void *calldata)
{
    static unsigned int client_id;

    XaceAuthAvailRec *rec = calldata;

#if 0
    if (!dixPrivateKeyRegistered(asec_client_key)
	    || !dixRegisterPrivateKey(asec_client_key, PRIVATE_CLIENT, 0)) {
	LogMessage(X_INFO, "ALTSecurity: could not register private key asec_client_key\n");
    }
#endif

    if (!dixPrivateKeyRegistered(asec_client_key)) {
	LogMessage(X_INFO, "ALTSecurity: ALTSecAuth asec_client_key is not registered\n");
	return;
    }

    if (rec) {
	ClientPtr pClient = rec->client;
	ALTSecClientPtr subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

	if (subj->uid == priv_uid || subj->uid == 0)
	    return;

	rec->status = BadAccess;

	return;

	LocalClientCredRec *creds;
	ALTSecClientPtr pClientPriv;

	pClientPriv->SelDelegationTime = asecInitTime;
	pClientPriv->client_id = client_id++;
	if (!GetLocalClientCreds(pClient, &creds) && creds != NULL) {
	    pClientPriv->uid = creds->euid;
	    FreeLocalClientCreds(creds);
	} else {
	    pClientPriv->uid = (uid_t) -1;
	}
#if 0
	if (dixPrivateKeyRegistered(asec_client_key))
	    dixSetPrivate(&pClient->devPrivates, asec_client_key, pClientPriv);
	else
	    LogMessage(X_INFO, "ALTSecurity: ALTSecAuth asec_client_key is not registered\n");
#endif
    }
}
#endif

void
ALTSecProperty(CallbackListPtr *pcbl, void *userdata, void *calldata)
{
    XacePropertyAccessRec *rec = calldata;

    PropertyPtr pProp = *rec->ppProp;
    ATOM name = (*rec->ppProp)->propertyName;
    ALTSecClientPtr subj, obj;
    Mask allowed = ALTSecResourceMask | DixReadAccess;

    for (int i = 0; ALTSecSharedProps[i] != NULL; i++)
	if (!strncmp(ALTSecSharedProps[i], NameForAtom(name), strlen(ALTSecSharedProps[i])))
	    return;

    if (rec->access_mode & DixPostAccess)
	return;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);
    /* obj = dixLookupPrivate(&wClient(rec->pWin)->devPrivates, asec_client_key); */
    obj = dixLookupPrivate(&pProp->devPrivates, asec_prop_key);

    if (rec->access_mode & DixCreateAccess) {
	/* Label newly created object */
	obj->uid = subj->uid;
    } else {
	if ((subj->uid == priv_uid || subj->uid == 0)
		&& (rec->access_mode & allowed))
	    return;

	while (pProp->propertyName != name || obj->uid != subj->uid) {
	    if ((pProp = pProp->next) == NULL)
		break;
	    obj = dixLookupPrivate(&pProp->devPrivates, asec_prop_key);
	}

	if (pProp)
	    *rec->ppProp = pProp;
	else {
	    rec->status = BadMatch;
	    LogMessage(X_INFO, "ALTSecProperty: BadMatch for request for property %s of client uid %d for client uid %d\n", NameForAtom(name), obj->uid, subj->uid);
	    return;
	}
    }

#if 0
    if (subj->uid == 0
	    || subj->uid == priv_uid
	    || subj->uid == obj->uid)
	return;
#endif
    if (subj->uid == obj->uid)
	return;

    if ((rec->access_mode | allowed) != allowed) {
	LogMessage(X_INFO, "ALTSecProperty: request for property %s of client uid %d is not allowed for client uid %d\n", NameForAtom(name), obj->uid, subj->uid);
	rec->status = BadAccess;
    }
#if 0
    PropertyPtr prop = rec->ppProp;
    char *name = NameForAtom(prop->propertyName);
    /* LogMessage(X_INFO, "Access property\n"); */
    if (rec->access_mode & DixWriteAccess) {
	LogMessage(X_INFO, "DixWriteAccess: %s\n", name);
	return;
    }
    if (rec->access_mode & DixReadAccess) {
	LogMessage(X_INFO, "DixReadAccess: %s\n", name);
	rec->status = BadAccess;
	return;
    }
#endif
}

void
ALTSecSelection(CallbackListPtr *pcbl, void *userdata, void *calldata)
{
    XaceSelectionAccessRec *rec = calldata;

    /* serverClient can do anything */
    if (rec->client == serverClient) {
	LogMessage(X_INFO, "Access selection by serverClient\n");
	return;
    }

    Selection *pSel = *rec->ppSel;
    Atom name = pSel->selection;
    const char *atom_name = NameForAtom(name);

    for (int i = 0; ALTSecSharedSels[i] != NULL; i++)
	if (!strncmp(ALTSecSharedSels[i], NameForAtom(name), strlen(ALTSecSharedSels[i])))
	    return;

    LogMessage(X_INFO, "Access selection: %s\n", atom_name);

    if (!strcmp(atom_name, "_NET_SYSTEM_TRAY_S0")) {
	LogMessage(X_INFO, "Got _NET_SYSTEM_TRAY_S0, proceed\n");
	rec->status = Success;
	return;
    }

    if (rec->access_mode & DixSetAttrAccess)
	return;

#if 0
    LocalClientCredRec *creds;
    GetLocalClientCreds(rec->client, &creds);
    int cpid = creds->pid;
    FreeLocalClientCreds(creds);

    GetLocalClientCreds(pSel->client, &creds);
    int spid = creds->pid;

    if (rec->access_mode & DixCreateAccess)
	LogMessage(X_INFO, "DixCreateAccess, %s, pids %d %d\n", atom_name, cpid, spid);
    if (rec->access_mode & DixSetAttrAccess) {
	LogMessage(X_INFO, "DixSetAttrAccess, %s, pids %d %d\n", atom_name, cpid, spid);
#if 0
	if (pSel->client != rec->client)
	    LogMessage(X_INFO, "Clients are different\n");
#endif
    }

    if (rec->access_mode & DixReadAccess)
	LogMessage(X_INFO, "DixReadAccess, %s, pids %d %d\n", atom_name, cpid, spid);
#endif

    if (rec->access_mode & (DixGetAttrAccess | DixReadAccess)) {
	LogMessage(X_INFO, "DixGetAttrAccess, %s\n", atom_name);
	LocalClientCredRec *creds;
	if (GetLocalClientCreds(rec->client, &creds) || creds == NULL) {
	    rec->status = BadMatch;
	    return;
	}

	int recuid = creds->euid;
	FreeLocalClientCreds(creds);
	LogMessage(X_INFO, "%d, client uid %d requests selection %s\n", rec->access_mode, recuid, atom_name);

	if (GetLocalClientCreds(pSel->client, &creds) || creds == NULL) {
	    rec->status = BadMatch;
	    return;
	}

	int seluid = creds->euid;
	FreeLocalClientCreds(creds);
#if 0
	while (pSel->selection != name || recuid != seluid) {
	    if ((pSel = pSel->next) == NULL)
		break;

	    GetLocalClientCreds(pSel->client, &creds);
	    if (creds)
		seluid = creds->euid;
	    FreeLocalClientCreds(creds);
	    LogMessage(X_INFO, "%d, *** client uid %d requests selection %s owned by uid %d\n", rec->access_mode, recuid, atom_name, seluid);
	}

	if (pSel) {
	    LogMessage(X_INFO, "pSel is not empty\n");
	    *rec->ppSel = pSel;
	} else {
	    LogMessage(X_INFO, "pSel *is* empty\n");
	    rec->status = BadMatch;
	    return;
	}
#endif
	while (pSel) {
	    if ((pSel->selection == name)
		    && !GetLocalClientCreds(pSel->client, &creds)
		    && creds != NULL) {
		seluid = creds->euid;
		FreeLocalClientCreds(creds);

		LogMessage(X_INFO, "%d, requested selection %s registered by uid %d\n", rec->access_mode, atom_name, seluid);

		if (recuid == seluid) {
		    *rec->ppSel = pSel;
		    break;
		}
	    }

	    pSel = pSel->next;
	}

	if (pSel == NULL)
	    rec->status = BadMatch;
    }
#if 0
    if (rec->access_mode & DixReadAccess) {
	LogMessage(X_INFO, "DixReadAccess, %s\n", name);
	rec->status = BadAccess;
    }
#endif
}

void
ALTSecClient(CallbackListPtr *pcbl, void *userdata, void *calldata)
{
    XaceClientAccessRec *rec = calldata;
    Mask allowed = ALTSecClientMask;

    ALTSecClientPtr subj, obj;

    subj = dixLookupPrivate(&rec->client->devPrivates, asec_client_key);

    if (subj->uid == priv_uid || subj->uid == 0)
	return;

    obj = dixLookupPrivate(&rec->target->devPrivates, asec_client_key);

    if (subj->uid == obj->uid ||
	    (rec->access_mode | allowed) == allowed)
	return;

    rec->status = BadAccess;
    LogMessage(X_INFO, "ALTSecurity: deny client request of uid %d to uid %d\n", subj->uid, obj->uid);
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

    if (XaceRegisterCallback(XACE_EXT_ACCESS, ALTSecExtension, NULL) != TRUE)
	FatalError("ALTSecurity: could not register extension dispatch callback\n");

    if (XaceRegisterCallback(XACE_SELECTION_ACCESS, ALTSecSelection, NULL) != TRUE) {
	FatalError("ALTSecurity: could not register selection callback\n");
    }

    if (XaceRegisterCallback(XACE_SERVER_ACCESS, ALTServerAccess, NULL) != TRUE)
	FatalError("ALTSecurity: could not register server access callback\n");

    ALTSecClientPtr pClientPriv = dixLookupPrivate(&serverClient->devPrivates, asec_client_key);
    LocalClientCredRec *creds;
    if (!GetLocalClientCreds(serverClient, &creds) && creds != NULL) {
	LogMessage(X_INFO, "ALTSecurity: serverClient pid = %d, uid == %d\n", creds->pid, creds->euid);
	FreeLocalClientCreds(creds);
    }
    pClientPriv->client_id = 0;
    pClientPriv->uid = 0;
}

/* vim:set sw=4 noet: */
