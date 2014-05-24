package nl.bruijnzeels.tim.rpki.ca
package core

import java.util.UUID

import common.cqrs.Event

sealed trait CaEvent extends Event

case class CaCreated(id:UUID, name: String) extends CaEvent
