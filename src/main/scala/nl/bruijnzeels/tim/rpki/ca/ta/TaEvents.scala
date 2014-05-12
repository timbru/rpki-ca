package nl.bruijnzeels.tim.rpki.ca.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import java.security.KeyPair
import net.ripe.ipresource.IpResourceSet

sealed trait TaEvent extends Event

case class TaCreated(name: String) extends TaEvent
case class TaResourcesUpdated(resources: IpResourceSet) extends TaEvent
case class TaKeyPairCreated(keyPair: KeyPair) extends TaEvent

