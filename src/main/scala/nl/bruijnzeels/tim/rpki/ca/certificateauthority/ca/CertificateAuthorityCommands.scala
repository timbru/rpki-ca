package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import common.cqrs.Command
import java.util.UUID

sealed trait CertificateAuthorityCommand extends Command {
  def id: UUID
}

case class CertificateAuthorityCreate(id: UUID, name: String) extends CertificateAuthorityCommand
case class CertificateAuthorityAddParent(id: UUID, parentXml: String) extends CertificateAuthorityCommand
