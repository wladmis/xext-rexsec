#ifndef _ALTSEC_H
#define _ALTSEC_H
#include <privates.h>

extern DevPrivateKeyRec asec_client_key_rec;
extern DevPrivateKeyRec asec_window_key_rec;
extern DevPrivateKeyRec asec_prop_key_rec;

extern const Mask ALTSecResourceMask;
extern const Mask ALTSecSecurityWindowExtraMask;
extern const Mask ALTSecSecurityRootWindowExtraMask;

extern uid_t priv_uid;

#define asec_client_key (&asec_client_key_rec)
#define asec_prop_key (&asec_prop_key_rec)
#define asec_window_key (&asec_window_key_rec)

#endif
