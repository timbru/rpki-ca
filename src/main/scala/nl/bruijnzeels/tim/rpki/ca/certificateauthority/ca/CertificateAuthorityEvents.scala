package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import java.util.UUID

import common.cqrs.Event

sealed trait CertificateAuthorityEvent extends Event

case class CertificateAuthorityCreated(aggregateId: UUID, name: String) extends CertificateAuthorityEvent

