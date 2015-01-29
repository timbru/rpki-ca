package nl.bruijnzeels.tim.rpki
package ca
package rc
package child

import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassEvent
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject

sealed trait ChildEvent extends ResourceClassEvent {
  def childId: UUID
}

case class ChildCreated(resourceClassName: String, childId: UUID, entitledResources: IpResourceSet) extends ChildEvent
case class ChildUpdatedResourceEntitlements(resourceClassName: String, childId: UUID, entitledResources: IpResourceSet) extends ChildEvent
case class ChildReceivedCertificate(resourceClassName: String, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent

