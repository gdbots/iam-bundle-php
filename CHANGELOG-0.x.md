# CHANGELOG for 0.x
This changelog references the relevant changes done in 0.x versions.


## v0.2.2
* Fix bug in `Auth0UserProvider` where Auth0 may return an array in `$jwt->aud`.  Instead of using the aud property we add `<argument>%env(AUTH0_API_IDENTIFIER)%</argument>` to the service and directly reference the expected property on the JWT.


## v0.2.1
* Use `GetNodeBatchRequestHandler` since `GetRoleBatchRequestHandler` has been removed from gdbots/ncr v0.3.0.
* Add policy caching to `PbjxPermissionVoter`, defaults to 300 seconds.
* Use `GetNodeBatchRequestHandler` to get roles in `Auth0Controller` instead of going to Ncr direct.


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
