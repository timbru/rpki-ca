package nl.bruijnzeels.tim.rpki.ca.ta

import java.util.UUID

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial

sealed trait TaEvent extends Event

case class TaError(id: UUID, message: String) extends TaEvent
case class TaCreated(id: UUID, name: String) extends TaEvent
case class TaSignerCreated(id: UUID, signingMaterial: SigningMaterial) extends TaEvent

sealed trait TaSignerEvent extends TaEvent

case class TaSignerPublished(id: UUID, crl: X509Crl, mft: ManifestCms) extends TaSignerEvent


