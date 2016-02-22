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
import nl.bruijnzeels.tim.rpki.common.domain.RoaAuthorisation

/**
  * Because there can be more than one resource class holding certificates for resources,
  * and the certified resources may change over time (even move from one class to the other),
  * decided to keep ROA Prefix config at a higher level.
  *
  * Actual ROAs can be generated in the appropriate resource class whenever there is a change.
  */
case class RoaConfiguration(roaAuthorisations: List[RoaAuthorisation] = List.empty) {


  def applyEvents(events: List[RoaConfigurationEvent]): RoaConfiguration = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: RoaConfigurationEvent): RoaConfiguration = event match {
    case added: RoaConfigurationPrefixAdded => copy(roaAuthorisations = roaAuthorisations :+ added.roaAuthorisation)
    case removed: RoaConfigurationPrefixRemoved => copy(roaAuthorisations = roaAuthorisations.filter(_ != removed.roaAuthorisation))
  }

  def addRoaAuthorisation(roaAuthorisation: RoaAuthorisation) = RoaConfigurationPrefixAdded(roaAuthorisation)
  def removeRoaAuthorisation(roaAuthorisation: RoaAuthorisation) = RoaConfigurationPrefixRemoved(roaAuthorisation)

  def findRelevantRoaPrefixes(relevantResources: IpResourceSet): List[RoaAuthorisation] = roaAuthorisations.filter(auth => relevantResources.contains(auth.roaPrefix.getPrefix))
}



