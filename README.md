RPKI - CA
================

License
-------
This code is distributed under the BSD License.

Description
-----------
This code started life as a pet project to allow me to play around with scala, and concepts such as
event sourcing and CQRS, on a domain that I am very familiar with. Later this code was used as the
base for my work on proof of concept code for the work on the RPKI Repository Delta Protocol that
I am involved with at the IETF:
https://tools.ietf.org/html/draft-tbruijnzeels-sidr-delta-protocol-03

That said, I plan to keep working on this code, time permitting, and over time evolve this into
its own stand-alone RPKI suite supporting operating:
 * A Trust Anchor (locally)
 * Any number of Certification Authorities under a local TA or remote TAs (using up-down)
 * A local publication server
 
