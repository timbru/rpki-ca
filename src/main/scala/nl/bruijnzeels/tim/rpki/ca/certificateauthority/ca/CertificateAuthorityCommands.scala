package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import common.cqrs.Command
import java.util.UUID
import java.net.URI

sealed trait CertificateAuthorityCommand extends Command {
  def id: UUID
}

case class CertificateAuthorityCreate(id: UUID, name: String, baseUrl: URI, rrdpNotifyUrl: URI) extends CertificateAuthorityCommand
case class CertificateAuthorityAddParent(id: UUID, parentXml: String) extends CertificateAuthorityCommand
case class CertificateAuthorityPublish(id: UUID) extends CertificateAuthorityCommand
