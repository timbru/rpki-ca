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