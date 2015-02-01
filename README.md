RPKI - CA
================

License
-------
This code is distributed under a BSD style License. See:
https://github.com/timbru/rpki-ca/blob/master/LICENSE.txt

Description
-----------
This code started life as a pet project to allow me to play around with scala, and concepts such as
event sourcing and CQRS, on a domain that I am very familiar with. Later this code was used as the
base for my work on proof of concept code for the RPKI Repository Delta Protocol that I am involved
with at the IETF:

https://tools.ietf.org/html/draft-tbruijnzeels-sidr-delta-protocol-03

That said, I plan to keep revisiting this code from time to time and evolve this into its own
stand-alone RPKI suite. Currently this suite supports the following:
 * A Trust Anchor (locally)
 * A Certification Authorities under a local TA
 * A local RRDP publication server

Future plans include:
 * Use persistent storage using an embedded file based DB (now everything is in memory)
 * Support snapshotting aggregate roots to improve performance
 * Sign and verify events (and snapshots) using a secret key to make this tamper evident
 * Allow CAs to have child CAs (i.e. not just under the local TA)
 * Allow CAs to have a remote parent (support up-down)
 * Let CAs manage ROAs
 * Introduce UI based on HTML5 + REST (possibly using Angular)
 * Add CLI wrapper for REST-full API to allow easy scripting (also run this headless?)

Comments and contributions welcome, but remember.. this is a bit of a pet project. Therefore response
may be slow, and some stuff I just want to play with for the fun of it.. ;)

If any of this is useful for you feel free to re-use within the BSD licence parameters.
