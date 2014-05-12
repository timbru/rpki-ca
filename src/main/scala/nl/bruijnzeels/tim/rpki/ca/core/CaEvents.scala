package nl.bruijnzeels.tim.rpki.ca
package core

import common.cqrs.Event

sealed trait CaEvent extends Event

case class CaCreated(name: String) extends CaEvent
