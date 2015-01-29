package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import common.cqrs.Command
import java.util.UUID
import java.net.URI
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId

sealed trait CertificateAuthorityCommand extends Command

case class CertificateAuthorityCreate(aggregateId: UUID, name: String, baseUrl: URI, rrdpNotifyUrl: URI) extends CertificateAuthorityCommand {
  def versionedId = VersionedId(aggregateId)
}
case class CertificateAuthorityAddParent(versionedId: VersionedId, parentXml: String) extends CertificateAuthorityCommand
case class CertificateAuthorityPublish(versionedId: VersionedId) extends CertificateAuthorityCommand
