RPKI - CA
================

License
-------
This code is distributed under a BSD style License. See:
https://github.com/timbru/rpki-ca/blob/master/LICENSE.txt

Description
-----------
This code started life as a pet project to allow me to play around with scala, and concepts such as
event sourcing and CQRS, on a domain that I am very familiar with. Since then I have started using
this code to do R&D and proof of concept work. It is on my to do list to change the package structure
and license to RIPE NCC - though I have done a lot of work in my own time, I also spent company time
on the R&D work - so it's only fair.

Currently this code supports:
 * Running a TA
 * Running any number of CAs under a TA
 * Running any number of CAs under another CA
 * Issuing ROAs
 * Basic extending and shrinking of resources to child CA, re-issuance waits for request by child
 * Will re-issue ROAs when republishing and resources changed
 * Child CA can handle if resource class disappears
 * Publishing using a built-in RRDP server (but see below, not production ready)

Future ideas (not in order):
 * Improve resource changes
   * Force shrink issued certificates when resources are lost, on publish (just like ROAs immediately after update)
   * Soft revoke child when no longer eligible? I.e. let Child do a revoke request? Protocol unclear on this I believe
   * Hard shrink child resources (pro-actively re-issue after time X, X can also be 0 seconds..)
 * Support key rolls
 * Extract library and proof-of-concept implementation code
   * Allow use of code as library with DSL
   * Separate operational main such as RRDP proof of concept to its own implementation
 * Sign events in event store in library -> make this tamper evident
 * Support persistent storage in library (to disk / allow injection of some data store)
 * Support remote parents (real up-down) in implementation
 * Support remote child (real up-down) in implementation
 * Support remote publication server in implementation
 * API and/or CLI wrapper for implementation

Comments and contributions welcome, but remember.. this is a bit of a pet project. Therefore response
may be slow, and some stuff I just want to play with for the fun of it.. ;)
