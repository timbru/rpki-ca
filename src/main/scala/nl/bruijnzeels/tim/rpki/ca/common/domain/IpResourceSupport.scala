/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
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
package nl.bruijnzeels.tim.rpki.ca.common.domain

import net.ripe.ipresource.IpResourceSet
import net.ripe.ipresource.IpResourceType
import scala.collection.JavaConverters._
import java.lang.IllegalArgumentException
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload

object IpResourceSupport {

  def getEntitledResourcesOfType(entitledResources: IpResourceSet, resourceType: IpResourceType) = {
    new IpResourceSet(entitledResources.iterator().asScala.flatMap(r => if (r.getType() == resourceType) { List(r) } else { List() }).toList.asJava)
  }

  def validateRequestedResources(entitledResources: IpResourceSet, requestedResources: IpResourceSet) = {
    if (!entitledResources.contains(requestedResources)) {
      val overclaiming = new IpResourceSet(requestedResources)
      overclaiming.removeAll(entitledResources)
      throw new IllegalArgumentException("Requesting unentitled resources: " + overclaiming)
    } else {
      requestedResources
    }
  }

  def determineResources(entitledResources: IpResourceSet, request: CertificateIssuanceRequestPayload) = {

    val resources = new IpResourceSet()

    val requestedAsn = request.getRequestElement().getAllocatedAsn() match {
      case null => getEntitledResourcesOfType(entitledResources, IpResourceType.ASN)
      case asn => validateRequestedResources(entitledResources, asn)
    }
    resources.addAll(requestedAsn)

    val requestedIpv4 = request.getRequestElement().getAllocatedIpv4() match {
      case null => getEntitledResourcesOfType(entitledResources, IpResourceType.IPv4)
      case ipv4 => validateRequestedResources(entitledResources, ipv4)
    }
    resources.addAll(requestedIpv4)

    val requestedIpv6 = request.getRequestElement().getAllocatedIpv6() match {
      case null => getEntitledResourcesOfType(entitledResources, IpResourceType.IPv6)
      case ipv6 => validateRequestedResources(entitledResources, ipv6)
    }
    resources.addAll(requestedIpv6)

    resources
  }

}