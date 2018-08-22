flux-security version 0.2.0 - 2018-08-22
----------------------------------------

### New Features

 * add mechanism argument to `flux_sign_wrap(3)` (#75)
 * add new function `flux_sign_unwrap_anymech(3)` (#75)
 * move default config file to `$sysconfdir/flux/security/conf.d`
   and add a default config file for signing (#76)
 * add sign_curve signing mechanism (#68)

### Cleanup

 * add pkg-config m4 to support side-installed autotools (#77)


flux-security version 0.1.0 - 2018-05-22
----------------------------------------

 * Initial bare-bones release, signing and context API only.

