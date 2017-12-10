# CHANGELOG for 0.x
This changelog references the relevant changes done in 0.x versions.


## v0.2.0
__BREAKING CHANGES__

* Require `"gdbots/ncr-bundle": "~0.3"` and `"gdbots/iam": "~0.2"`.
* Remove `src/Resources/config/services.xml`.  Use Symfony prototype to import and 
  autoconfigure all services from `gdbots/iam` in your app configuration.
* Move `PbjxPermissionValidator` to `Gdbots\Bundle\IamBundle\Validator` to match convention.
* Move `auth0_jwt` service configurations to `src/Resources/config/`.
* Remove `GdbotsIamExtension` since we're not autoloading config any more.


## v0.1.0
* Initial version.
