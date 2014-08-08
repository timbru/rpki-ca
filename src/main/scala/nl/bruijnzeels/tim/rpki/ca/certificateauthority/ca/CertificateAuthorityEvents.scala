package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import java.util.UUID
import common.cqrs.Event
import java.net.URI

sealed trait CertificateAuthorityEvent extends Event

case class CertificateAuthorityCreated(aggregateId: UUID, name: String, baseUrl: URI) extends CertificateAuthorityEvent
case class CertificateAuthorityAddedParent(aggregateId: UUID) extends CertificateAuthorityEvent

