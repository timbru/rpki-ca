package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import common.cqrs.Command

sealed trait CertificateAuthorityCommand extends Command

case class CreateCertificateAuthorityCommond(name: String) extends CertificateAuthorityCommand
