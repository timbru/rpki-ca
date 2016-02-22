/**
 * Copyright (c) 2014-2016 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package nl.bruijnzeels.tim.rpki.ca.roas

import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.RpkiTest
import nl.bruijnzeels.tim.rpki.common.domain.RoaAuthorisation

class RoaConfigurationTest extends RpkiTest {

  test("Should add Roa confifuration prefix") {
    val roaPrefixAdded = RoaConfigurationPrefixAdded(RoaAuthorisation(asn = "AS1", roaPrefix = "192.168.0.0/24"))

    val roaConfiguration = new RoaConfiguration()
    roaConfiguration.roaAuthorisations should have size (0)

    val roaConfigurationAfterAdd = roaConfiguration.applyEvent(roaPrefixAdded)
    roaConfigurationAfterAdd.roaAuthorisations should have size (1)
  }

  test("Should remove Roa confifuration prefix") {
    val roaPrefixAdded = RoaConfigurationPrefixAdded(RoaAuthorisation(asn = "AS1", roaPrefix = "192.168.0.0/24"))

    val roaConfiguration = new RoaConfiguration()
    roaConfiguration.roaAuthorisations should have size (0)

    val roaConfigurationAfterAdd = roaConfiguration.applyEvent(roaPrefixAdded)
    roaConfigurationAfterAdd.roaAuthorisations should have size (1)

    val roaPrefixRemoved = RoaConfigurationPrefixRemoved(RoaAuthorisation(asn = "AS1", roaPrefix = "192.168.0.0/24"))
    val roaConfigurationAfterRemove = roaConfigurationAfterAdd.applyEvent(roaPrefixRemoved)
    roaConfigurationAfterRemove.roaAuthorisations should have size (0)
  }

  test("Should filter relevant ROA Prefixes for resources") {
    val roaConfigurationWithPrefixes = new RoaConfiguration().applyEvents(List(
      RoaConfigurationPrefixAdded(RoaAuthorisation(asn = "AS1", roaPrefix = "192.168.0.0/16")),
      RoaConfigurationPrefixAdded(RoaAuthorisation(asn = "AS1", roaPrefix = "10.0.0.0/16"))
    ))

    roaConfigurationWithPrefixes.findRelevantRoaPrefixes(IpResourceSet.parse("192.168.0.0/16")) should have size(1)
  }

}
