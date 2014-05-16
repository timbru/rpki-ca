package nl.bruijnzeels.tim.rpki.ca
package core

import common.cqrs.Event
import java.util.UUID

sealed trait CaEvent extends Event

case class CaCreated(id:UUID, name: String) extends CaEvent
