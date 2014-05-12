package nl.bruijnzeels.tim.rpki.ca
package core

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command

sealed trait CaCommand extends Command

case class CreateCaCommond(name: String) extends CaCommand
