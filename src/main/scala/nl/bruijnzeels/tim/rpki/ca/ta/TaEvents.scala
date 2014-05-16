package nl.bruijnzeels.tim.rpki.ca.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import java.security.KeyPair
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import java.util.UUID

sealed trait TaEvent extends Event

case class TaCreated(id: UUID, name: String) extends TaEvent
case class TaSignerCreated(id: UUID, signingCertificate: SigningCertificate) extends TaEvent

sealed trait TaSignerEvent extends TaEvent


