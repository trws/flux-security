flux-security version 0.5.0 - 2021-09-03
----------------------------------------

## New Features

 * imp: add run command for prolog/epilog support (#123)
 * check file permissions and ownership of files when running
   privileged code (#122)

## Testing
 
 * ci: switch to github actions (#121)
 * bump minimum jansson version to 2.10 (#114)


flux-security version 0.4.0 - 2020-03-19
----------------------------------------

## New Features

 * lib: add `flux_sign_wrap_as(3)` (#108)
 * imp: add support for IMP exec command (#104, #109)
 * imp: add support for IMP kill command (#110, #111)
 * update internal libtomlc99 to latest (#98)

## Testing

 * build/test under asan and ubsan, fix errors (#97)
 * fix tests when run on nosuid filesystems (#100)


flux-security version 0.3.0 - 2019-01-11
----------------------------------------

### Fixes

 * lib: make aux get/set interface like flux-core api (#88)

### New Features

 * license: re-publish project under LGPLv3 (#87, #89, #91)
 * lib: add interface to query flux-security version (#86)
 * lib: support library versioning for libflux-security.so (#93)

### Cleanup

 * convert to libsodium base64 implementation (#85)


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

