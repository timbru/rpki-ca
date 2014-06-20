package nl.bruijnzeels.tim.rpki.ca
package core

import java.util.UUID
import common.cqrs.Event
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.common.domain.Revocation

sealed trait CaEvent extends Event

case class CaCreated(id: UUID, name: String) extends CaEvent

