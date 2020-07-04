# CHANGELOG for 2.x
This changelog references the relevant changes done in 2.x versions.


## v2.0.0
__BREAKING CHANGES__

* Upgrade to support Symfony 5 and PHP 7.4.
* Uses `"gdbots/iam": "^2.0"`
* Uses `"gdbots/ncr": "^2.0"`
* Supports `"auth0/auth0-php": "^7.0"`
* Adds ncr permission checks in `PbjxPermissionValidator`. Commands and requests with node_ref(s) will translate into a permission in the format of `vendor:label:action`, e.g. `acme:article:publish`. This is in addition to the message permission check itself `gdbots:ncr:command:publish-node`. This is being done to eliminate the need to implement all of the ncr commands/events/requests at the app level but still have precise permission controls.
