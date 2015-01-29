package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta

import java.net.URI
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId

sealed trait TrustAnchorCommand extends Command

case class TrustAnchorCreate(aggregateId: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationUri: URI, rrdpNotifyUrl: URI) extends TrustAnchorCommand {
  def versionedId = VersionedId(aggregateId)
}
case class TrustAnchorPublish(versionedId: VersionedId) extends TrustAnchorCommand
case class TrustAnchorAddChild(versionedId: VersionedId, childId: UUID, childXml: String, childResources: IpResourceSet) extends TrustAnchorCommand

case class TrustAnchorProcessResourceListQuery(versionedId: VersionedId, childId: UUID, provisioningCmsObject: ProvisioningCmsObject) extends TrustAnchorCommand